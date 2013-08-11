class LoginController < ApplicationController

# ----------
# error handling
# ----------
  rescue_from RuntimeError, Exception, :with => :error


  # error = end point for API errors
  def error
    session[:error] = 99 if (session[:error].nil? || session[:error] == 0)
    #session[:errorDescription] = 'There was an error' if session[:errorDescription].blank?
    render :index
  end
# ----------

# ----------
#  def index
#      session[:deterLoginStatus] = '(index)'
#      create
#  end
# ---------

  def new
    session[:deterLoginStatus] = '(new)'
    render :index
  end

  # get the current DeterLab version for display via a SOAP transaction
  def getDeterVersion
    if session[:deter_version].nil? || session[:deter_version].blank? 
        client = Savon.client(
          :wsdl => "https://users.isi.deterlab.net:52323/axis2/services/ApiInfo?wsdl",
          :log_level => :debug, 
          :log => true, 
          :pretty_print_xml => true,
          :soap_version => 2,
          :namespace => 'http://api.testbed.deterlab.net/xsd',
          :logger => Rails.logger,
          :filters => :password,
	  # client SSL options
	  :ssl_verify_mode => :none
          )

        response = client.call(:get_version)
        session[:deter_version] = response.to_hash[:get_version_response][:return][:version]
	client = nil
    end
    session[:deter_version]
  end

  # load the current user profile: first template, then data
  def loadProfile(client)
      # first get the template, aka "description"
      response = client.call(
                   :get_profile_description,
		   "message" => {'uid' => '', :order! => [:uid] }
	         )
      if response.success? == true  
          # stash data away in the session by parsing profile tree: an array of hashes
          a = response.to_hash[:get_profile_description_response][:return][:attributes]
          a.each do |h|
	      # create a slot for this attribute
	      session[ 'up_' + h[:description] ] = ''

	      # save other attributes as well
	      session[ 'up_' + h[:description] + '_access' ] = h[:access]
	      session[ 'up_' + h[:description] + '_name' ] = h[:name]
          end

	  # now get the data for that template
          response = client.call(
	               :get_user_profile,
	               "message" => {'uid' => @_current_user, :order! => [:uid] }
		      )
	  if response.success? == true
	      session[:deterLoginStatus] = 'getUserProfile...OK'

	      #logger.debug response.to_hash.inspect
	      # stash data away in the session by parsing profile tree: an array of hashes
	      a = response.to_hash[:get_user_profile_response][:return][:attributes]
              a.each do |h|
		  # save the data for this attribute
 	          session[ 'up_' + h[:description] ] = h[:value]
              end
	  else
	      session[:errorDescription] = 'getUserProfile...FAIL'
	      raise RuntimeError, "SOAP Error"
	  end
      else
	  raise RuntimeError, "SOAP Error"
      end
      response
  end

  # create = might be login (should use flash hash?)
  def create
    # clear the "we are doing profiles" flag and the "manage password" flag
    session[:pwrdmgmt] = session[:profile] = nil

    # always make sure you have the deter version (ensures connectivity if nothing else)
    getDeterVersion

    # really need a session ID
    if session[:session_id].blank?
        flash.now[:error] = 'No session ID!' 
	if request.session_options[:id].blank?
            flash.now[:error] = 'Really no session ID!' 
	    session[:deterLoginCode] = 4
	    render :index
	    return
	else
	    session[:session_id] = request.session_options[:id]
	end
    end

    session[:deterLoginStatus] = '(create)'

    if @_current_user.blank? && !params['uid'].blank?
	uid = params['uid']
	password = params['password']
	encoded_data = Base64.encode64(password)

        session[:deterLoginStatus] = '(create) Logging in...'

	# build a SOAP transaction pathway
        client = Savon.client(
          :wsdl => "https://users.isi.deterlab.net:52323/axis2/services/Users?wsdl",
          :log_level => :debug, 
          :log => true, 
          :pretty_print_xml => true,
          :soap_version => 2,
          :namespace => 'http://api.testbed.deterlab.net/xsd',
          :logger => Rails.logger,
          :filters => :password,
	  :raise_errors => false,
	  # client SSL options
	  :ssl_verify_mode => :none
          )
        session[:deterLoginStatus] = 'SOAP client...'

	#
	# two step process: requestChallenge, then challengeResponse
	#

	#requestChallenge, uid={value} types={'clear'}; response has type={'clear'}, validity={stuff}
        session[:deterLoginStatus] = 'requestChallenge...'
        response = client.call(
	             :request_challenge, 
		     "message" => {'uid' => uid, 'types' => 'clear', :order! => [:uid, :types] }
		   )
	logger.debug response.to_hash.inspect
	if response.success? == true
            session[:deterLoginStatus] = 'requestChallenge...OK'
	    id = response.to_hash[:request_challenge_response][:return][:challenge_id]

	    #challengeResponse, challengeID={validity}, responseData={base64-encoded-password}
            session[:deterLoginStatus] = 'challengeResponse...'
            response = client.call(
	                   :challenge_response,
			   "message" => {'challengeID' => id, 'responseData' => encoded_data, :order! => [:responseData, :challengeID] }
			)
	    logger.debug response.to_hash.inspect
	    if response.success? == true
                session[:deterLoginStatus] = 'challengeResponse...OK'
	        session[:deterLoginCode] = rc = 2
		session[:deterLoginStatus] = 'Login OK'
	    	@_current_user = session[:current_user_id] = uid

		# need a place to put the x509 certs: AppConfig.cert_directory
		unless File.directory?(AppConfig.cert_directory) 
		    if File.exist?(AppConfig.cert_directory)
		        File.unlink(AppConfig.cert_directory)
		    end
		    Dir.mkdir(AppConfig.cert_directory)
		    File.chmod(0700,AppConfig.cert_directory)
		end

		# handle the x509 certs: parse them into two different files
	        x509s = Base64.decode64(response.to_hash[:challenge_response_response][:return])
		lines = x509s.split("\n")
		fname = AppConfig.cert_directory + '/' +  ('cert-' + session[:session_id] + '.pem')
		logger.debug fname.inspect
		File.delete(fname) if File.exists?(fname)
		certFile = File.new(fname, 'w',0600)
		lines.each do |l|
		    certFile.print l,"\n"
		    break if l.match(/END CERTIFICATE/)
		end
		certFile.close
		File.chmod(0400,fname)
		session[:certFile] = fname

		fname = AppConfig.cert_directory + '/' + ('key-' + session[:session_id] + '.pem')
		logger.debug fname.inspect
		flag = 0
		File.delete(fname) if File.exists?(fname)
		keyFile = File.new(fname, 'w',0600)
		lines.each do |l|
		    flag = 1 if l.match(/BEGIN RSA PRIVATE/)
		    if flag == 1
		    	keyFile.print l,"\n"
		    end
		end
		keyFile.close
		File.chmod(0400,fname)
		session[:keyFile] = fname

		# now that you have certs, create a more secure SOAP transaction pathway
		client = nil # does this destroy the object? I hope so. I don't know.
                client = Savon.client(
                  :wsdl => "https://users.isi.deterlab.net:52323/axis2/services/Users?wsdl",
                  :log_level => :debug, 
                  :log => true, 
                  :pretty_print_xml => true,
                  :soap_version => 2,
                  :namespace => 'http://api.testbed.deterlab.net/xsd',
                  :logger => Rails.logger,
                  :filters => :password,
	          :raise_errors => false,
	          # client SSL options
		  :ssl_verify_mode => :none,
	          :ssl_cert_file => session[:certFile],
	          :ssl_cert_key_file => session[:keyFile]
                  )

		# load the profile for this user, you will need it later
                response = loadProfile(client)
	        if response.success? == true
		    session[:deterLoginStatus] = 'getUserProfile...OK'
		else
		    session[:deterLoginStatus] = 'getUserProfile...FAIL'
	  	    raise RuntimeError, "SOAP Error"
		end
	    else 
                session[:errorDescription] = 'challengeResponse...FAIL'
	        session[:deterLoginCode] = rc = 1
		session[:deterLoginStatus] = 'Login failed: bad credentials'
	    end
	else
	    session[:deterLoginCode] = rc = 1
	    session[:deterLoginStatus] = 'requestChallenge...FAIL: '
	    generic = response.to_hash[:fault][:reason][:text]
	    detail = response.to_hash[:fault][:detail][:users_deter_fault][:deter_fault][:detail_message]
	    if !detail.blank?
	        session[:errorDescription] = detail
	    else
	        session[:errorDescription] = generic
	    end
	    raise RuntimeError, 'SOAP Error'
	end
    else
        session[:deterLoginCode] = rc = 2
	session[:deterLoginStatus] = 'Login OK'
	if session[:current_user_id].blank?
	    session[:current_user_id] = uid
	end
    end # if no current user
    session[:deterLoginCode] = rc
    if rc == 2 && !session[:original_target].blank?
	tmp = session[:original_target]
	session[:original_target] = nil
        redirect_to tmp
    else
        render :index
    end
  end

  def end_session
    logger.debug "----- in the end_session method: session hash follows"
    logger.debug session.inspect


    session[:original_target] = @_current_user = session[:current_user_id] = nil
    session[:error] = session[:profile] = session[:pwrdmgmt] = nil
    session[:pwrderror] = false

    # scrub any and all x509-related files
    toscrub = Array.new
    toscrub.push(session[:certFile]) unless session[:certFile].blank?
    toscrub.push(session[:keyFile]) unless session[:keyFile].blank?
    logger.debug toscrub.inspect
    toscrub.each do |f|
	next unless File.exists?(f)
        bytes = File.size?(f)
        if bytes
	    File.chmod(0600,f)
	    fh = File.new(f,"w+")
	    fh.rewind
	    bytes.times do
	        fh.print "x"
	    end
	    fh.truncate(0)
	    fh.close
        end
	File.delete(f)
    end # any SSL-related files to clobber
    session[:deterLoginCode] = 0
  end

  # destroy = logout & timeout
  def destroy
    session[:deterLoginStatus] = 'Logged out'
    end_session
    redirect_to "/login"
    #render :index
  end

  # profshow = show the profile
  def profshow
    @_current_user = session[:current_user_id] if @_current_user.blank?

    # what if we need to log in first?
    if @_current_user.blank?
        session[:original_target] = request.fullpath
    else
        session[:original_target] = nil
    end

    session['saveProfileStatus'] = nil
    session['profile'] = 'show'
    session['pwrdmgmt'] = nil
    render :index
  end

  # profedit = edit the profile
  def profedit
    @_current_user = session[:current_user_id] if @_current_user.blank?
    # what if we need to log in first?
    if @_current_user.blank?
        session[:original_target] = request.fullpath
    end

    session['saveProfileStatus'] = nil
    session['profile'] = 'edit'
    session['pwrdmgmt'] = nil
    render :index
  end

  # if the user requests it, save the profile
  def saveProfile
    text = ''
    if session[:profile] == 'update'
	text = 'working...'
    	changes = Array.new
	session.each do |k, v|
	    next if v.nil?
	    next if params[k].nil?
	    if k.match(/^up_/) && !k.match(/_(access|name)$/)
		unless params[k] == v
		    text = text + k + ' changed from {' + v + '} to {' + params[k] + '}<br>'
		    mykey = session[k + '_name']
		    changes.push({'name' => mykey, 'value' =>params[k], 'delete' => 0})
		end
	    end
	end

	# save any changed data elements
	unless changes.empty?
	    # build a SOAP transaction pathway
	    client = nil # just in case
            client = Savon.client(
              :wsdl => "https://users.isi.deterlab.net:52323/axis2/services/Users?wsdl",
              :log_level => :debug, 
              :log => true, 
              :pretty_print_xml => true,
              :soap_version => 2,
              :namespace => 'http://api.testbed.deterlab.net/xsd',
              :logger => Rails.logger,
              :filters => :password,
	      :raise_errors => false,
	      # client SSL options
	      :ssl_verify_mode => :none,
	      :ssl_cert_file => session[:certFile],
	      :ssl_cert_key_file => session[:keyFile]
              )

	      text = text + '<br><strong>' + 'Profile update '
	      # send the changes to the server as a SOAP transaction
              response = client.call(
	                     :change_user_profile,
	                     "message" => {'uid' => session[:current_user_id], :order! => [:uid, :changes], 'changes' => changes }
			     )
	      if response.success? == true
		  a = response.to_hash[:change_user_profile_response][:return]
		  if !a[:success]
		      text = text + 'FAILED at Tranaction Level: ' + a[:reason]
		  else
	              text = text + 'OK'
		      # now update our cache
                      response = loadProfile(client)
	              if response.success? == true
		          session[:deterLoginStatus] = 'getUserProfile...OK'
	              else
		          session[:errorDescription] = 'getUserProfile...FAIL'
	  	    	  raise RuntimeError, "SOAP Error"
		      end
	          end
	      else
	          session[:errorDescription] = text = text + 'FAILED at SOAP Level'
	  	  raise RuntimeError, "SOAP Error"
	      end
	      text = text + '</strong><br>'
        end
    else
        text = 'no triggers for saveProfile'
    end
    text
  end

  # profsave = update the changed profile
  def profsave
    @_current_user = session[:current_user_id] if @_current_user.blank?
    session['profile'] = 'update'
    session['saveProfileStatus'] = saveProfile
    session['profile'] = 'show'
    session['pwrdmgmt'] = nil
    #render :index
    redirect_to("action" => 'profshow')
  end

  # pwrdedit = change your password
  def pwrdedit
    session['profile'] = nil
    session['pwrdmgmt'] = 'edit'

    @_current_user = session[:current_user_id] if @_current_user.blank?
    # what if we need to log in first?
    if @_current_user.blank?
        session[:original_target] = request.fullpath
    else
        session[:original_target] = nil
    end

    render :index
  end

  # pwrdsave = save your changed password
  def pwrdsave
    session[:errorDescription] = session[:error] = session['profile'] = session['pwrdmgmt'] = nil
    session[:pwrderror] = false

    text = ''

    # validate the input
    unless params['newpass1'] == params['newpass2']
        session[:errorDescription] = t('password_page.failedtext') + ' because password & confirmation do not match'
        logger.debug session[:errorDescription]
	session[:pwrderror] = true
	#raise RuntimeError, 'Bad Password'
    end
    pwrd = params['newpass1']
    if pwrd.blank?
        session[:errorDescription] = t('password_page.failedtext') + ' because password is blank'
        logger.debug session[:errorDescription]
	session[:pwrderror] = true
	#raise RuntimeError, 'Bad Password'
    end
    if pwrd.length < 8 || !pwrd.match(/[0-9]/) || ! pwrd.match(/[a-zA-Z]/)
        session[:errorDescription] = t('password_page.failedtext') + 
	  ' because password is too weak: must be at least 8 characters and contain at least one digit and one letter'
	session[:pwrderror] = true
    end

    # if the new password is acceptable, send it to the server
    unless session[:pwrderror]
        # make the SOAP call to change the password for this user
        client = Savon.client(
          :wsdl => "https://users.isi.deterlab.net:52323/axis2/services/Users?wsdl",
          :log_level => :debug, 
          :log => true, 
          :pretty_print_xml => true,
          :soap_version => 2,
          :namespace => 'http://api.testbed.deterlab.net/xsd',
          :logger => Rails.logger,
          :filters => :password,
	  :raise_errors => false,
	  # client SSL options
	  :ssl_verify_mode => :none,
	  :ssl_cert_file => session[:certFile],
	  :ssl_cert_key_file => session[:keyFile]
          )

	# send the changes to the server as a SOAP transaction
        response = client.call(
	               :change_password,
	               "message" => {'uid' => session[:current_user_id], 'newPass' => pwrd, :order! => [:uid, :newPass] }
	           )
	if response.success?
            a = response.to_hash[:change_password_response][:return]
            if a == true
	        text = text + 'OK'
            else
	        text = text + 'FAILED at Tranaction Level: ' + a[:reason]
	        session[:errorDescription] = text + 'FAILED at SOAP Level'
		session[:pwrderror] = true
	        #raise RuntimeError, session[:errorDescription]
	    end
	else
	    msg = response.to_hash[:fault][:detail][:users_deter_fault][:deter_fault][:detail_message]
	    logger.debug msg
	    logger.debug '1'
	    session[:errorDescription] = text + 'FAILED at SOAP Level'
	    logger.debug '2'
	    if !msg.blank?
	        session[:errorDescription] = session[:errorDescription] = t('password_page.failedtext') + 'because ' + msg
	        text = text + ' ' + msg
	    end
	    logger.debug '3'
	    session[:pwrderror] = true
	    logger.debug msg
	    #raise RuntimeError, session[:errorDescription]
	end
	logger.debug '4'
	text = text + '</strong><br>'
	session[:deterLoginStatus] = text

	# destroy the SOAP client, you are done with it
        client = nil
    end

    logger.debug msg
    #render :index
    if session[:pwrderror]
        myaction = 'pwrdedit'
    else
	session[:notice] = 'Password changed'
        myaction = 'profshow'
    end
    redirect_to("action" => myaction)
  end

end
