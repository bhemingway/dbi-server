require 'base64'

module ApplicationHelper
  # are we logged in or not? return a state as a code: 0=initial, 1=trying, 2=worked, 3=failed
  def loginStatus
      rc = 0
      if @current_user.blank?  # some flavor of not logged in
          if params['uid'].blank? == false && params['password'].blank? == false # trying to log in
              rc = 1
          end
      else
          rc = 2
      end
      rc
  end

  # are we logged in or not? return a human-readable string to that effect
  def loginStatusText
    status = loginStatus
    if status == 2
       'Log Out'
    else
       'Log In'
    end
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

  # validate the credentials supplied by the user via a SOAP transaction
  def loginValidate
    status = Array.new
    if @current_user.blank?
	status.push('No user ID, logging in...')

	uid = params['uid']
	password = params['password']
	encoded_data = Base64.encode64(password)
	status.push('user ID=(' + uid + ')')
	status.push('password=(' + password + ')')
	status.push('encoded password=(' + encoded_data + ')')

	# build a SOAP transaction pathway
	status.push('firing up the SOAP client to verify credentials...')
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

	# two step process: requestChallenge, then challengeResponse

	#requestChallenge, uid={value} types={'clear'}; response has type={'clear'}, validity={stuff}
	status.push('requestChallenge...')
        response = client.call(
	             :request_challenge, 
		     "message" => {'uid' => uid, 'types' => 'clear' } 
		   )
	logger.debug response.to_hash.inspect
	if response.success? == true
	    status.push('requestChallenge...OK')
	    id = response.to_hash[:request_challenge_response][:return][:challenge_id]

	    #challengeResponse, challengeID={validity}, responseData={base64-encoded-password}
	    status.push('challengeResponse...')
            response = client.call(:challenge_response, "message" => {'challengeID' => id, 'responseData' => encoded_data } )
	    logger.debug response.to_hash.inspect
	    if response.success? == true
		#status.push(debug(response.to_hash))
	        sslCert = Base64.decode64(response.to_hash[:challenge_response_response][:return])
	        status.push('challengResponse: Security payload...',sslCert)
	    else 
	        status.push('challengeResponse failed...')
	    end
	else
	    status.push('requestChallenge failed...')
	    if response.to_hash[:fault][:reason][:text].nil? == false
	        status.push('requestChallenge Generic SOAP fault...',response.to_hash[:fault][:reason][:text]);
	    else
	        status.push('requestChallenge' + response.to_hash[:fault][:detail][:users_deter_fault][:deter_fault][:error_message]);
	    end
	    status.push('giving up.')
	end

    end # if no current user

    time = Time.new
    status.push('Done at ' + time.strftime("%Y-%m-%d %H:%M:%S") + ' UTC')

    status_string = '<ul><li>' + status.join("</li>\n<li>") + "</li>\n</ul>" 
    raw(status_string)
  end # loginValidate
end # module ApplicationHelper
