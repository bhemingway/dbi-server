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
      rc = 0
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
       text = link_to('Log Out', "login", { :confirm => "#{translate( :are_you_sure )}", :method => :delete, :class => 'action' } )
    else
       text = link_to("Log In", "login", :method => :create, :class => 'action')
    end
    raw(text)
  end

  # what do we want to tell the user about logging in?
  def loginMessage
    status = loginStatus
    if status != 2 and status != 0
	message = '<span style="color: red">' + t('front.loginbox.loginfail') + '</span>'
	message = message + ' <cite>' + session[:deterLoginStatus] + '</cite>'
	raw(message)
    end
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
			   "message" => {'challengeID' => id, 'responseData' => encoded_data,:order! => [:responseData, :challengeID] }
			)
	    logger.debug response.to_hash.inspect
	    if response.success? == true
                session[:deterLoginStatus] = 'challengeResponse...OK'
	        sslCert = Base64.decode64(response.to_hash[:challenge_response_response][:return])
        	rc = 2
		session[:deterLoginStatus] = 'Login OK'
		if session[:current_user_id].blank?
	    	    session[:current_user_id] = uid
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

end # module ApplicationHelper
