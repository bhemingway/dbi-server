require 'base64'

module ApplicationHelper

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

  # are we logged in or not? return a state as a code: 0=initial, 1=trying, 2=worked, 3=failed
  def loginStatus
      if params[:logout].blank? == false
          @_current_user = session[:current_user_id] =  nil
	  session[:deterLoginStatus] = session[:deter_version] = nil
	  session.each do |k, v|
	      if k.match(/^up_/)
	      	session.delete(k)
	      end
	  end
	  if !session[:certFile].blank?
	      bytes = File.size?(session[:certFile])
	      if bytes
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
	  end
	  if !session[:keyFile].blank?
	      bytes = File.size?(session[:keyFile])
	      if bytes
	          keyFile = File.new(session[:keyFile],"w+")
	          keyFile.rewind
	          bytes.times do
	              keyFile.print "x"
	          end
	          keyFile.truncate(0)
	          keyFile.close
	          File.delete(session[:keyFile])
	      end
	      session[:keyFile] = nil
	  end
      end
      if session[:current_user_id].blank? 
          rc = 0
      else
          @_current_user = session[:current_user_id]
	  rc = 2
      end
      if @_current_user.blank?  # some flavor of not logged in
          session[:deterLoginStatus] = 'None'
          if params['uid'].blank? == false && params['password'].blank? == false # trying to log in
	      rc = loginValidate
          end
      else
          rc = 2
      end
      rc
  end

  # are we logged in or not? return a human-readable string to that effect
  def loginStatusText
    status = loginStatus
    text = ''
    if status == 2
       text = 'Logged in as ' + @_current_user + ' (' + session[:up_Name] + ')'
    else
       text = 'Not logged in'
    end
    text
  end

  # what do we want to tell the user about logging in?
  def loginMessage
    status = loginStatus
    message = t('front.para1') 
    if status != 2 and status != 0
	message = '<span style="color: red">' + t('front.loginbox.loginfail') + '</span>'
	#message = message + ' <cite>' + session[:deterLoginStatus] + '</cite>'
    end
    raw(message)
  end

  # validate the credentials supplied by the user via a SOAP transaction
  def loginValidate
    session[:deterLoginStatus] = 'Unset'
    if @_current_user.blank?
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
	    	session[:current_user_id] = uid

		# handle the x509 certs: parse them into two different files
	        x509s = Base64.decode64(response.to_hash[:challenge_response_response][:return])
		lines = x509s.split("\n")
		fname = Rails.root.join('tmp') + ('cert-' + request.session_options[:id] + '.pem')
		logger.debug fname.inspect
		certFile = File.new(fname, 'w')
		lines.each do |l|
		    certFile.print l,"\n"
		    break if l.match(/END CERTIFICATE/)
		end
		certFile.close
		session[:certFile] = fname

		fname = Rails.root.join('tmp') + ('key-' + request.session_options[:id] + '.pem')
		logger.debug fname.inspect
		flag = 0
		keyFile = File.new(fname, 'w')
		lines.each do |l|
		    flag = 1 if l.match(/BEGIN RSA PRIVATE/)
		    if flag == 1
		    	keyFile.print l,"\n"
		    end
		end
		keyFile.close
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
                response = client.call(
	                       :get_user_profile,
			       "message" => {'uid' => uid, :order! => [:uid] }
			    )
	        if response.success? == true
		    logger.debug response.to_hash.inspect
		    # stash data away in the session by parsing profile tree: an array of hashes
		    a = response.to_hash[:get_user_profile_response][:return][:attributes]
		    a.each do |h|
			if h[:description] == "The user's real world name"
			    session[:up_Name] = h[:value]
			end

			# save entire profile in session for now
			session[ 'up_' + h[:description] ] = h[:value]
		    end
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

  # if the user wants to see it, show the profile
  def showProfile
      if params[:profile].blank? == false
	output = Array.new
	output.push('<table align="center">')
	session.each do |k, v|
	    if k.match(/^up_/) && !k.match('up_Name') 
		output.push('<tr>')
		output.push('<td><strong>' + k[3, k.length - 3] + '</strong></th>')
	        output.push('<td>' + v + '</td>')
		output.push('</tr>')
	    end
	end
	output.push('</table>')
	raw(output.join("\n"))
      end
  end

end # module ApplicationHelper
