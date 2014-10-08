class LoginController < ApplicationController

# ----------
# error handling
# ----------
#  rescue_from RuntimeError, Exception, :with => :error


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

  def index
    getDeterVersion
  end

  def new
    session[:deterLoginStatus] = '(new)'
    render :index
  end

  # get the current DeterLab version for display via a SOAP transaction
  def getDeterVersion
    logger.debug "getDeterVersion...START OF CALL"

    # expire the version after 15 minutes
    if session[:deter_version_date].nil? or session[:deter_version_date] < 15.minutes.ago
      session[:deter_version] = nil
    end
    
    # if no valid cache'd version, fetch it
    if session[:deter_version].nil? || session[:deter_version].blank? 
        logger.debug "getDeterVersion...calling SOAP"
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
        session[:deter_version] = response.to_hash[:get_version_response][:return][:version] + '/' +
                                  response.to_hash[:get_version_response][:return][:patch_level]
        logger.debug "getDeterVersion...used SOAP"

	client = nil
	response = nil
	session[:deter_version_date] = Time.now
    else 
        logger.debug "getDeterVersion...used cached version in session"
    end
    logger.debug "getDeterVersion: returning " + session[:deter_version].inspect
    session[:deter_version]
  end

  # load the current user profile: first template, then data
  def loadProfile(client, user_id=@_current_user, name_flag=0)
      name = '' # in case we are mapping uids to names

      # first get the template, aka "description"
      response = client.call(
                   :get_profile_description,
		   "message" => {'uid' => '', :order! => [:uid] }
	         )
      if response.success? == true  
          # stash data away in the session by parsing profile tree: an array of hashes
          a = response.to_hash[:get_profile_description_response][:return][:attributes]
	  if name_flag == 0
              a.each do |h|
	          # create a slot for this attribute
	          session[ 'up_' + h[:description] ] = ''
    
	          # save other attributes as well
	          session[ 'up_' + h[:description] + '_access' ] = h[:access]
	          session[ 'up_' + h[:description] + '_name' ] = h[:name]

		  # suggested length of zero is not helpful
		  len = h[:length_hint].to_i
		  if len <= 0
		      len = 50
		  end
	          session[ 'up_' + h[:description] + '_length_hint' ] = len.to_s

	          # sort key is special
	          session[ 'up_sort_' +  sprintf("%08d",h[:ordering_hint].to_i) ] = 'up_' + h[:description]
              end
          end
	  # now get the data for that template
          response = client.call(
	               :get_user_profile,
	               "message" => {'uid' => user_id, :order! => [:uid] }
		      )
	  if response.success? == true
	      if name_flag == 0
	          session[:deterLoginStatus] = 'getUserProfile...OK'
	      end

	      #logger.debug response.to_hash.inspect
	      # stash data away in the session by parsing profile tree: an array of hashes
	      a = response.to_hash[:get_user_profile_response][:return][:attributes]
              a.each do |h|
		  if name_flag == 0
		      # save the data for this attribute
 	              session[ 'up_' + h[:description] ] = h[:value]
		  else
		      #logger.debug h.inspect
		      if h[:name] == 'name'
		          name = h[:value]
		      end
		  end
	      end
	  else
	      session[:errorDescription] = ('getUserProfile(' + user_id + ')...FAIL')
	      raise RuntimeError, ("SOAP Error: " + session[:errorDescription])
	  end
      else
	  raise RuntimeError, "SOAP Error"
      end
      if name_flag == 0
          response
      else
          name
      end
  end

  # create = might be login (should use flash hash?)
  def create

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

    if @_current_user.blank? && params['uid'].blank?
        end_session
        session[:deterLoginCode] = rc = 0
    elsif @_current_user.blank? && !params['uid'].blank? && params['password'].blank?
	session[:deterLoginCode] = rc = 1
	session[:deterLoginStatus] = 'Login failed: bad credentials'
    elsif @_current_user.blank? && !params['uid'].blank? && !params['password'].blank?
	uid = params['uid']
	password = params['password']
	encoded_data = Base64.encode64(password)

        session[:deterLoginStatus] = '(create) Logging in as ' + uid + '...' 

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
	if client.nil?
	    raise RuntimeError, "SOAP Error (could not create client)"
	end
	#logger.debug client.inspect
	
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
		session[:deterLoginStatus] = 'Login OK [1]'
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
	session[:deterLoginStatus] = 'Login OK [2]'
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
    session[:deterLoginCode] = session[:error] = session[:profile] = session[:pwrdmgmt] = nil
    session[:pwrderror] = false
    session.each do |k, v|
        next unless k.match(/^(up|proj)_|(_members$)/)
	session[k] = nil
    end

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
	render :index
	return
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
	render :index
	return
    end

    session['saveProfileStatus'] = nil
    session['profile'] = 'edit'
    session['pwrdmgmt'] = nil
    render :index
  end

  # if the user requests it, save the profile
  def saveProfileController
logger.debug '==>saveProfileController starts...'
logger.debug session.inspect
    text = ''
    if session['profile'] == 'update'
logger.debug '==>0...'
	text = 'working...'

	# need a superset of keys so that if blank in one, but not in the other, we still process the k
    	kh = Hash.new
	session.each do |k, v|
	    next unless k.match(/^up_/) 
	    kh[k] = 'found'
	end
	params.each do |k, v|
	    next unless k.match(/^up_/) 
	    kh[k] = 'found'
	end
logger.debug kh.inspect

	# find all the changes
    	changes = Array.new
	kh.each do |k, x|
logger.debug ('==>' +  k + ' 1...')
	    # selection based on keys
	    next unless k.match(/^up_/) 
	    next if k.match(/_(access|name|length|order)$/)
	    next if k.match(/_(sort_|length_hint)/)
logger.debug ('==>' +  k + ' 2...')

	    # if the form did not post this key, then the corresponding value is not editable
	    next unless params.has_key?(k)
logger.debug ('==>' +  k + ' 3...')

	    # get the old value for this key out of sessions hash
	    v = session[k]

	    # selection based on data values
	    next if (v.nil? or v.blank?) and (params[k].nil? or params[k].blank?)
logger.debug ('==>' +  k + ' 4...')
	    #next if params[k] == v
	    next if params[k].to_s == v.to_s
logger.debug ('==>' +  k + ' 5...')

	    # if we get here, we have new data
	    old = v
	    if old.nil? or old.blank?
		old = '-blank-'
	    end
	    new = params[k]
	    if new.nil? or new.blank?
	        new = ''
	    end
	    text = text + k + ' changed from {' + old.to_s + '} to {' + new.to_s + '}<br>'
logger.debug ('==>' +  k + ' changed from {' + old.to_s + '} to {' + new.to_s + '}')
	    mykey = session[k + '_name']
	    changes.push({'name' => mykey, 'value' =>new.to_s, 'delete' => 0})
logger.debug ('==>(' + mykey.to_s + ')|' + new.to_s)
	end
logger.debug changes.inspect

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
		  # should changes array be checked against the return?

		  # "a" should be an array of hashes but sometimes it is just the has
		  # so make the hash into an array of hashes
    		  if a.class.to_s == 'Array'
		      b = a
                  else
	              # fake out an array of one element: the hash returned
                      tmp = Array.new
	              tmp.push(a)
	              b = tmp
		  end

		  flag = 1
		  b.each do |h|
		      if h.has_key?('success') && h[:success] != true
		      	  flag = 0
		      end
		  end
		  if flag == 0
		      text = text + 'FAILED at Transaction Level: '
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
        text = 'no triggers for saveProfileController'
    end
    text
  end

  # profsave = update the changed profile
  def profsave
    @_current_user = session[:current_user_id] if @_current_user.blank?
    session['profile'] = 'update'
    session['saveProfileStatus'] = saveProfileController
logger.debug '==> saveProfileController output...'
logger.debug session['saveProfileStatus']
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
	render :index
	return
    else
        session[:original_target] = nil
    end

    render :index
  end

  # validate the proposed password for either change password or reset password
  def checkPassword
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
    pwrd
  end

  # pwrdsave = save your changed password
  def pwrdsave
    session[:errorDescription] = session[:error] = session['profile'] = session['pwrdmgmt'] = nil
    session[:pwrderror] = false

    text = ''

    # validate the input
    pwrd = checkPassword

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
	        text = text + 'FAILED at Transaction Level: ' + a[:reason]
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
	        session[:errorDescription] = session[:errorDescription] = t('password_page.failedtext') + ' because ' + msg
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

  # pwrdforgot1 = step 1 of handling password reset: form to request a challenge
  def pwrdforgot1
      end_session
      render :index
  end

  # pwrdforgot2 = step 2 of handling password reset: action to actually request a challenge
  def pwrdforgot2
    # compose the URL prefix to the challenge: http://host/pwrdreset1?challenge=
    logger.debug "-----pwrdforgot2 starts"
    logger.debug request.inspect
    url = request.protocol + request.host_with_port + '/pwrdreset1?challenge='
    logger.debug url.inspect

    text = ''

    # send SOAP transaction to request a challenge
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
	  :ssl_verify_mode => :none
          )

	# send the changes to the server as a SOAP transaction
        response = client.call(
	               :request_password_reset,
	               "message" => {'uid' => params['uidreset'], 'urlPrefix' => url, :order! => [:uid, :urlPrefix] }
	           )
	if response.success?
            a = response.to_hash[:request_password_reset_response][:return]
            if a == true
	        text = text + 'OK'
            else
	        text = text + 'FAILED at Transaction Level: ' + a[:reason]
	        session[:errorDescription] = text + 'FAILED at SOAP Level'
		session[:pwrderror] = true
	        #raise RuntimeError, session[:errorDescription]
	    end
	else
	    msg = response.to_hash[:fault][:detail][:users_deter_fault][:deter_fault][:detail_message]
	    logger.debug msg
	    session[:errorDescription] = text + 'FAILED at SOAP Level'
	    if !msg.blank?
	        session[:errorDescription] = session[:errorDescription] = t('password_page.failedtext') + ' because ' + msg
	        text = text + ' ' + msg
	    end
	    session[:pwrderror] = true
	    #raise RuntimeError, session[:errorDescription]
	end
	text = text + '</strong><br>'
	session[:deterLoginStatus] = text

	# destroy the SOAP client, you are done with it
        client = nil
    end
      
    session[:notice] = 'Password reset requested'
    redirect_to("action" => 'create')
  end

  # pwrdreset1 = step 3 of handling password reset: enter proposed password and challenge
  def pwrdreset1
      end_session
      render :index
  end

  # pwrdreset2 = step 4 of handling password reset: use the challenge and proposed password
  def pwrdreset2
    text = ''

    # validate the input
    pwrd = checkPassword

    # if the new password is acceptable, send it to the server along with the challenge
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
	  :ssl_verify_mode => :none
          )

	# send the changes to the server as a SOAP transaction
        response = client.call(
	               :change_password_challenge,
	               "message" => {'challengeID' => params['challenge'], 'newPass' => pwrd, :order! => [:challengeID, :newPass] }
	           )
	if response.success?
            a = response.to_hash[:change_password_challenge_response][:return]
            if a == true
	        text = text + 'OK'
            else
	        text = text + 'FAILED at Transaction Level: ' + a[:reason]
	        session[:errorDescription] = text + 'FAILED at SOAP Level'
		session[:pwrderror] = true
	        #raise RuntimeError, session[:errorDescription]
	    end
	else
	    msg = response.to_hash[:fault][:detail][:users_deter_fault][:deter_fault][:detail_message]
	    logger.debug msg
	    session[:errorDescription] = text + 'FAILED at SOAP Level'
	    if !msg.blank?
	        session[:errorDescription] = session[:errorDescription] = t('password_page.failedtext') + ' because ' + msg
	        text = text + ' ' + msg
	    end
	    session[:pwrderror] = true
	    #raise RuntimeError, session[:errorDescription]
	end
	text = text + '</strong><br>'
	session[:deterLoginStatus] = text

	# destroy the SOAP client, you are done with it
        client = nil
        session[:notice] = 'Password reset was accepted'
    end
    if session[:pwrderror]
	raise RuntimeError, session[:errorDescription]
    end
    render :index
  end

  # projlist = list projects available to this user
  def projlist
    @_current_user = session[:current_user_id] if @_current_user.blank?

    text = 'Project List'

    # what if we need to log in first?
    if @_current_user.blank?
        session[:original_target] = request.fullpath
	render :index
	return
    else
        session[:original_target] = nil
    end

    msg = session[:errorDescription ] = session['saveProfileStatus'] = session['profile'] = session['pwrdmgmt'] = nil

    # get the list of projects associated with this user with viewProjects()
    client = nil # does this destroy the object? I hope so. I don't know.
    pclient = Savon.client(
        :wsdl => "https://users.isi.deterlab.net:52323/axis2/services/Projects?wsdl",
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

    # query the server for all profiles as a SOAP transaction
    response = pclient.call(
                   :view_projects,
	           "message" => {'uid' => @_current_user, :order! => [:uid] }
	       )

    if response.success?
        a = response.to_hash[:view_projects_response][:return]
	logger.debug a.class
	logger.debug a.inspect
	if a.class.to_s == 'Array'
	    text = text + 'OK'
        elsif a.has_key?("reason")
	    text = text + 'FAILED at Transaction Level: ' + a[:reason]
	    session[:errorDescription] = text + 'FAILED at SOAP Level'
	    raise RuntimeError, session[:errorDescription]
	end
    else
	msg = response.to_hash[:fault][:detail][:projects_deter_fault][:deter_fault][:detail_message]
	logger.debug msg
	session[:errorDescription] = text + 'FAILED at SOAP Level'
	if !msg.blank?
	    session[:errorDescription] = session[:errorDescription] + ' Attempt to list projects failed because ' + msg
	    text = text + ' ' + msg
	end
	raise RuntimeError, session[:errorDescription]
    end

    # if there is just one project, a is a Hash. I pray that
    # if there are multiple projects, a is an Array of Hashes
    if a.class.to_s == 'Array'
	b = a
    else
	# fake out an array of one element: the hash returned
        tmp = Array.new
	tmp.push(a)
	b = tmp
    end

    # create a SOAP client for the Users service, so we can get people's names
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
    status = '?'

    # get the members for each project
    exps = Array.new
    members = Array.new
    b.each do |h|
        if h[:owner] == @_current_user
	    status = 'owner'
        end

	# get the key for this project
	k = 'proj_' + h[:project_id]

	# process members
	members.clear
	h[:members].each do |m|
	    unless m[:uid] == h[:owner]
	        members.push(loadProfile(client,m[:uid],1))
	        #members.push(m[:uid])
	    end
	end

	# stub out call to viewExperiments
	exps.clear
	if h[:project_id] == 'Tutorial2011'
	        #link_to('ExperimentOne', '/expershow?id=ExperimentOne')
	    exps.push(
		'<a href="/expershow?id=ExperimentOne">ExperimentOne</a>'
	    )
	elsif h[:project_id] == 'emulab-ops'
	        #link_to('ExperimentTwo', '/expershow?id=ExperimentTwo')
	    exps.push(
		'<a href="/expershow?id=ExperimentTwo">ExperimentTwo</a>'
	    )
	end

	# get attributes from the project profile
	desc = ''
	url = ''
	affil = ''
        response = pclient.call(
                       :get_project_profile,
	               "message" => {'projectid' => h[:project_id], :order! => [:projectid] }
	           )
        if response.success?
            projprof = response.to_hash[:get_project_profile_response][:return][:attributes]
	    #logger.debug projprof.inspect
	    #logger.debug projprof.class
	    if projprof.class.to_s == 'Hash'
		if projprof[:name] == 'description'
                    desc = projprof[:value]
		elsif projprof[:name] == 'URL'
                    url = projprof[:value]
		elsif projprof[:name] == 'affiliation'
                    affil = projprof[:value]
		end
	    else
		projprof.each do |z|
		    if z[:name] == 'description'
                        desc = z[:value]
		    elsif z[:name] == 'URL'
                        url = z[:value]
		    elsif z[:name] == 'affiliation'
                        affil = z[:value]
		    end
	        end
	    end
	end

	# set the session variables for this project
        session[k] = status
	if !members.empty?
	    l = h[:project_id] + '_members'
	    session[l] = members.sort.join(", ")
	end
	if !exps.empty?
	    l = h[:project_id] + '_exps'
	    session[l] = exps.sort.join(", ")
	end
	l = h[:project_id] + '_owner'
	session[l] = loadProfile(client,h[:owner],1)
	l = h[:project_id] + '_approved'
	session[l] = h[:approved]

	if !desc.blank?
	    l = h[:project_id] + '_desc'
	    session[l] = desc
	end
	if !url.blank?
	    l = h[:project_id] + '_url'
	    session[l] = url
	end
	if !affil.blank?
	    l = h[:project_id] + '_affil'
	    session[l] = affil
	end
    end

    # destroy the SOAP client for the Users service, you are done with it
    client = nil

    # destroy the SOAP client for the Projects service, you are done with it
    pclient = nil

    render :index
  end

  # expershow = show a specific experiment to the user
  def expershow
    @_current_user = session[:current_user_id] if @_current_user.blank?

    # what if we need to log in first?
    if @_current_user.blank?
        session[:original_target] = request.fullpath
	render :index
	return
    else
        session[:original_target] = nil
    end

    session['saveProfileStatus'] = session['profile'] = session['pwrdmgmt'] = nil

    # do we need to send data to the client?
    if !params['whichaction'].nil? && !params['whichaction'].blank? && params['whichaction'].match(/^download_/)
	@tmp = params['whichaction']
	@tag = @tmp[9, @tmp.length - 9]
	@key = 'attrib_' + @tag 
	@fn = @tag + '.txt'
	send_data(params[@key].to_s, :filename=>@fn)
	return
    end

    render :index
  end

  # experlist = list experiments available to this user
  def experlist
    @_current_user = session[:current_user_id] if @_current_user.blank?

    # what if we need to log in first?
    if @_current_user.blank?
        session[:original_target] = request.fullpath
	render :index
	return
    else
        session[:original_target] = nil
    end

    session['saveProfileStatus'] = session['profile'] = session['pwrdmgmt'] = nil

    # create a SOAP client for the Users service, so we can get people's names
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

    # get the list of projects associated with this user

    # for now, stub out viewExperiments() call
    plist = [
        {   'Name' => 'ExperimentOne',
	    'owner' => 'ricci',
	    'ReadProjects' => [ 
	        'Project X'
	    ],
	    'WriteProjects' => [ 
	        'Project Runway'
	    ],
	    'RealizeProjects' => [ 
	        'Project Runway'
	    ]
	},
        {   'Name' => 'ExperimentTwo',
	    'owner' => 'jsebes',
	    'ReadProjects' => [ 
	        'Project Runway'
	    ],
	    'WriteProjects' => [ 
	        'Project Runway'
	    ],
	    'RealizeProjects' => [ 
	        'Project Runway'
	    ]
	},
        {   'Name' => 'ExperimentThree',
	    'owner' => 'bfdh',
	    'ReadProjects' => [ 
	        'Project Your_voice'
	    ],
	    'WriteProjects' => [ 
	        'Project Runway'
	    ],
	    'RealizeProjects' => [ 
	        'Project X'
	    ]
	}
    ]

    #logger.debug 'Barg!'
    plist.each do |h|
        #logger.debug h.inspect

	# get the key for this experiment
	k = 'exper_' + h['Name']

	# store this experiment name for use later
        session[k] = loadProfile(client,h['owner'],1)

#-
#	# set the session variable for this project
#	z = Hash.new
#	['ReadProjects', 'WriteProjects', 'RealizeProjects'].each do |x|
#	    z[x] = h[x]
#	end
#        session[k] = z
#        logger.debug z.inspect
#-
    end

    client = nil

    render :index
  end

  # newproject = new project application form, part 0 (info)
  def newproject
    # no prerequisite
    render :index
  end

  # newproject = new project application form, part 1 (id self)
  def newproject1

    # prerequisite: form0 => cb1 & cb2
    flag = 0
    params.each do |k, v|
      flag += 1 if k.match('cb1') or k.match('cb2')
    end
    if flag.zero?
      redirect_to "action" => 'newproject', "alert" => t('newproject.out_of_order')
    else
      render :index
    end
  end

  # newproject = new project application form, part 2 (project leader info)
  def newproject2
    # prerequisite: form1 => usage_type
    flag = 0
    params.each do |k, v|
      flag += 1 if k.match('usage_type')
    end
    if flag.zero?
      redirect_to "action" => 'newproject', "alert" => t('newproject.out_of_order')
    else
      render :index
    end
  end

  # newproject3 = new project application form, part 3 (project info)
  def newproject3
    # prerequisite: form2 => f_name
    flag = 0
    params.each do |k, v|
      flag += 1 if k.match('f_name')
    end
    if flag.zero?
      redirect_to "action" => 'newproject', "alert" => t('newproject.out_of_order')
    else
      render :index
    end
  end

  # newproject4 = new project application form, part 4 (submit info)
  def newproject4
    render :index
  end

  # usage = current status of system, via API
  def usage
    render :index
  end

  # news = recent announcements from DeterLab
  def news
    render :index
  end

end
