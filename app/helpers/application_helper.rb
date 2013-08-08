require 'base64'

module ApplicationHelper

  # get the current DeterLab version for display via a SOAP transaction
  def deterVersion
    session[:deter_version]
  end

  # are we logged in or not? return a state as a code: 0=initial, 1=trying, 2=worked, 3=failed, 4=timed out
  def loginStatus
      rc = 0
      rc = session[:deterLoginCode].to_i unless session[:deterLoginCode].blank?
      if session.nil? or session.empty?
          rc = session[:deterLoginCode] = 4
      end

      # non-empty session implies that we are no longer timed out, but rather logged out
      if rc == 4 && (!session.nil? || !session.empty?)
          rc = session[:deterLoginCode] = 0
      end
      rc
  end

  # what do we want to tell the user about logging in?
  def loginMessage
    status = loginStatus
    message = t('front.para1') 
    if !session[:original_target].blank?
	message = '<span style="color: red">' + t('front.loginbox.loginfirst') + '</span>'
    elsif status != 2 and status != 0 and status != 4
	message = '<span style="color: red">' + t('front.loginbox.loginfail') + '</span>'
    end
    #message = message + ' <cite>' + session[:deterLoginStatus] + ' ' + status.to_s + '</cite>'
    raw(message)
  end

  # if the user requests it, save the profile
  def saveProfile
    text = ''
    if !session.nil? && !@_current_user.blank? && session[:profile] == 'update'
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
	                     "message" => {'uid' => @_current_user, :order! => [:uid, :changes], 'changes' => changes }
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
			  raise 'SOAP Error'
		      end
	          end
	      else
	          session[:errorDescription] = text = text + 'FAILED at SOAP Level'
		  raise 'SOAP Error'
	      end
	      text = text + '</strong><br>'
        end
    end
    if AppConfig.debug_visible
        raw(text)
    else
    	''
    end
  end

  # if the user wants to see it, show the profile
  def showProfile
      rc = loginStatus
      if rc == 2 && session[:profile].blank? == false 
	output = Array.new
	output.push('<table align="center" class="deter-block">')
	session.sort.each do |k, v|
	    if k.match(/^up_/) && !k.match(/_(access|name)$/)
		if v.blank?
		    tmp = ''
                else
		    tmp = v
                end
		output.push('  <tr>')
		output.push('    <td align="right"><strong>' + k[3, k.length - 3] + '</strong></td>')
	        output.push('    <td>' + tmp + '</td>')
		output.push('  </tr>')
	    end
	end
	output.push('</table>')
	raw(output.join("\n"))
      end
  end

end # module ApplicationHelper
