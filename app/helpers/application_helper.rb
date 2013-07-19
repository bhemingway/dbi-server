module ApplicationHelper
  # are we logged in or not? return a state as a code: 0=initial, 1=trying, 2=worked, 3=failed
  def loginStatus
      rc = 0
      if (@current_user.nil? or @current_user.length == 0) # some flavor of not logged in
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
    client = Savon.client('wsdl' => "https://users.isi.deterlab.net:52323/axis2/services/ApiInfo?wsdl")
    response = client.call(:get_version)
    debug(response)
  end
end
