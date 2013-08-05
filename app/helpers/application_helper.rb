require 'base64'

module ApplicationHelper

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
 	      session[ 'up_' + h[:description] ] = ''
          end

	  # now get the data for that template
          response = client.call(
	               :get_user_profile,
	               "message" => {'uid' => @_current_user, :order! => [:uid] }
		      )
	  if response.success? == true
	      #logger.debug response.to_hash.inspect
	      # stash data away in the session by parsing profile tree: an array of hashes
	      a = response.to_hash[:get_user_profile_response][:return][:attributes]
              a.each do |h|
	          if h[:description] == "The user's real world name"
		      session[:up_Name] = h[:value]
		  end

		  # save entire profile in session for now
		  session[ 'up_' + h[:description] ] = h[:value]
		  session[ 'up_' + h[:description] + '_access' ] = h[:access]
		  session[ 'up_' + h[:description] + '_name' ] = h[:name]
              end
	  else
	      session[:deterLoginStatus] = 'getUserfProfile...FAIL'
	  end
      end
      response
  end

  # get the current DeterLab version for display via a SOAP transaction
  def deterVersion
    if session[:deter_version] == nil
        client = Savon.client(
          :wsdl => "https://users.isi.deterlab.net:52323/axis2/services/ApiInfo?wsdl",
          :log_level => :debug, 
          :log => true, 
          :pretty_print_xml => true,
          :soap_version => 2,
          :namespace => 'http://api.testbed.deterlab.net/xsd',
          :logger => Rails.logger,
          :filters => :password
          )

        response = client.call(:get_version)
        session[:deter_version] = response.to_hash[:get_version_response][:return][:version]
    end
    session[:deter_version]
  end

  # are we logged in or not? return a state as a code: 0=initial, 1=trying, 2=worked, 3=failed, 4=timed out
  def loginStatus
      rc = 0
      if !params[:logout].blank? || session[:session_id].blank? 
          if session[:session_id].blank?
              rc = 4
	  end
          @_current_user = nil
	  if !session.nil? 
              session[:current_user_id] =  nil
	      session[:deterLoginStatus] = session[:deter_version] = nil
	      session.each do |k, v|
	          if !k.nil? && k.to_s.match(/^up_/)
	      	    session.delete(k)
	          end
	      end # for every key of the session hash
	      session[:deterLoginStatus] = 'timeout'
	  end # if no session id

	  if !session[:certFile].blank?
	      bytes = File.size?(session[:certFile])
	      if bytes
		  File.chmod(0600,session[:certFile])
	          certFile = File.new(session[:certFile],"w+")
	          certFile.rewind
	          bytes.times do
	              certFile.print "x"
	          end
	          certFile.truncate(0)
	          certFile.close
	          File.delete(session[:certFile])
	      end
	      session[:certFile] = nil
	  end # if nonblank cert file name

	  if !session[:keyFile].blank?
	      bytes = File.size?(session[:keyFile])
	      if bytes
		  File.chmod(0600,session[:keyFile])
	          keyFile = File.new(session[:keyFile],"w+")
	          keyFile.rewind
	          bytes.times do
	              keyFile.print "x"
	          end
	          keyFile.truncate(0)
	          keyFile.close
	          File.delete(session[:keyFile])
	      end # 
	      session[:keyFile] = nil
          end # if nonblank key file name
      elsif @_current_user.blank? && session[:current_user_id].blank?  # some flavor of not logged in
	  rc = 0
          session[:deterLoginStatus] = 'None'
          if (!params['uid'].nil? || params['uid'].blank? == false) && (!params['password'].nil? || params['password'].blank? == false) # trying to log in
	      rc = loginValidate
          end
      else # you are logged in
          @_current_user = session[:current_user_id]
          rc = 2
      end # logout or timeout vs other
      rc
  end

  # what do we want to tell the user about logging in?
  def loginMessage
    status = loginStatus
    message = t('front.para1') 
    if status != 2 and status != 0 and status != 4
	message = '<span style="color: red">' + t('front.loginbox.loginfail') + '</span>'
    end
    #message = message + ' <cite>' + session[:deterLoginStatus] + ' ' + status.to_s + '</cite>'
    raw(message)
  end

  # validate the credentials supplied by the user via a SOAP transaction
  def loginValidate
    session[:deterLoginStatus] = 'Unset'
    if session[:session_id].blank? && !@_current_user.blank?
        session[:deterLoginStatus] = 'Session timeout'
	rc = 4
    elsif @_current_user.blank? && params['uid'].blank?
        session[:deterLoginStatus] = 'No user and no UID'
	rc = 0
    elsif @_current_user.blank? && !params['uid'].blank?
	uid = params['uid']
	password = params['password']
	encoded_data = Base64.encode64(password)

        session[:deterLoginStatus] = 'Logging in...'

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
	  :raise_errors => false
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
        	rc = 2
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
		    session[:deterLoginStatus] = 'getUserfProfile...OK'
		else
		    session[:deterLoginStatus] = 'getUserfProfile...FAIL'
		end
	    else 
                session[:deterLoginStatus] = 'challengeResponse...FAIL'
		rc = 1
		session[:deterLoginStatus] = 'Login failed: bad credentials'
	    end
	else
	    rc = 1
	    session[:deterLoginStatus] = 'requestChallenge...FAIL: '
	    if response.to_hash[:fault][:reason][:text].nil? == false
	        session[:deterLoginStatus] = session[:deterLoginStatus] + 
		                             'requestChallenge Generic SOAP fault...' + 
					     response.to_hash[:fault][:reason][:text]
	    else
	        session[:deterLoginStatus] = session[:deterLoginStatus] + 
		                             'requestChallenge' + 
		                             response.to_hash[:fault][:detail][:users_deter_fault][:deter_fault][:error_message]
	    end
	end
    else
        rc = 2
	session[:deterLoginStatus] = 'Login OK'
	if session[:current_user_id].blank?
	    session[:current_user_id] = uid
	end
    end # if no current user
    rc
  end # loginValidate

  # if the user requests it, save the profile
  def saveProfile
    text = ''
    if !session.nil? && !@_current_user.blank? && params[:profile] == 'update'
    	changes = Array.new
	session.each do |k, v|
	    next if v.nil?
	    next if params[k].nil?
	    if k.match(/^up_/) && !k.match('up_Name')  && !k.match(/_(access|name)$/)
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
	                     "message" => {'uid' => @_current_user, :order! => [:uid, :changes], 'changes' => changes }
			     )
	      if response.success? == true
		  a = response.to_hash[:change_user_profile_response][:return]
		  if !a[:success]
		      text = text + 'FAILED at Tranaction Level: ' + a[:reason]
		  else
	              text = text + 'OK'
		      # now update our cache
                      response = client.call(
	                             :get_user_profile,
			             "message" => {'uid' => @_current_user, :order! => [:uid] }
			          )
	              if response.success? == true
		          #logger.debug response.to_hash.inspect
		          # stash data away in the session by parsing profile tree: an array of hashes
		          a = response.to_hash[:get_user_profile_response][:return][:attributes]
		          a.each do |h|
			      if h[:description] == "The user's real world name"
			          session[:up_Name] = h[:value]
			      end

			      # save entire profile in session for now
			      session[ 'up_' + h[:description] ] = h[:value]
			      session[ 'up_' + h[:description] + '_access' ] = h[:access]
			      session[ 'up_' + h[:description] + '_name' ] = h[:name]
		          end
	              else
		          session[:deterLoginStatus] = 'getUserfProfile...FAIL'
		      end
	          end
	      else
	          text = text + 'FAILED at SOAP Level'
	      end
	      text = text + '</strong><br>'
        end
    end
    raw(text)
  end

  # if the user wants to see it, show the profile
  def showProfile
      rc = loginStatus
      if rc == 2 && params[:profile].blank? == false 
	output = Array.new
	output.push('<table align="center" class="deter-block">')
	session.sort.each do |k, v|
	    if k.match(/^up_/) && !k.match('up_Name')  && !k.match(/_(access|name)$/)
		output.push('  <tr>')
		output.push('    <td align="right"><strong>' + k[3, k.length - 3] + '</strong></td>')
	        output.push('    <td>' + v + '</td>')
		output.push('  </tr>')
	    end
	end
	output.push('</table>')
	raw(output.join("\n"))
      end
  end

end # module ApplicationHelper
