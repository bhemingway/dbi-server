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
    a = 'You Are'
    b = ''
    c = t('rightgutter.loggedin');

    b = 'Not' if status != 2

    [a,b,c].join(' ').squeeze(' ')
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
    if @current_user.blank?
	uid = params['uid']
	password = params['password']

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

        response = client.call(:echo, "message" => {'param' => uid} )
        session[:loggedIn] = response.to_hash[:echo_response][:return]
    end
    session[:loggedIn]
  end
end
