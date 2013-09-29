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
      session[:deterLoginCode] = nil
      if session.nil? or session.empty?
          rc = session[:deterLoginCode] = 4
      elsif rc == 4 && (!session.nil? || !session.empty?) # non-empty session implies that we are no longer timed out, but rather logged out
          rc = session[:deterLoginCode] = 0
      else
          session[:deterLoginCode] = rc
      end
      rc
  end

  # what do we want to tell the user about logging in?
  def loginMessage
    status = loginStatus
    message = t('front.para1') 
    if status != 2 && !session[:original_target].blank?
	tmp = t('front.loginbox.loginfirst')
	tmp = t('front.loginbox.logintimeout') if status == 4
	message = '<span style="color: red">' + tmp + '</span>'
    elsif status != 2 and status != 0 and status != 4
	message = '<span style="color: red">' + t('front.loginbox.loginfail') + '</span>'
    end
    #message = message + ' <cite>' + session[:deterLoginStatus] + ' ' + status.to_s + '</cite>'
    raw(message)
  end

  # if the user requests it, save the profile
  def saveProfile
    logger.debug '==>saveProfile (helper version)'
return
    text = ''
    if !session.nil? && !@_current_user.blank? && session['profile'] == 'update'
    	changes = Array.new
	session.each do |k, v|
	    next if v.nil?
	    next if params[k].nil?
	    if k.match(/^up_/) && !k.match(/_(access|name|length|order)$/)
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
	output.push('<table align="center" class="dbi-profile">')
	session.sort.each do |sortkey, datakey|
	    next unless sortkey.match(/^up_sort/)
	    v = session[datakey]
            if v.blank?
		tmp = ''
            else
		tmp = v
            end
	    k = datakey
	    output.push('  <tr>')
	    output.push('    <td align="right" width="' + AppConfig.profile["name_col_width"] + '"><strong>' + k[3, k.length - 3] + '</strong></td>')
	    output.push('    <td>' + tmp + '</td>')
            output.push('  </tr>')
	end
	output.push('</table>')
	raw(output.join("\n"))
      end
  end

  # stub out viewExperiments call
  def experData(id)
    exper = nil
    # note; 'owner' comes from session[exper_{name}] now: want actual name not user id
    if id == 'ExperimentOne'
        exper = [
          { 
            'owner' => 'ricci', 
	    'proj'  => 'Tutorial2013 Project',
	    'stat'  => 'Unrealized',
	    'topol' => link_to('Topology','/expershow?id=ExperimentOne'),
	    'acts'  => link_to('Actions','/expershow?id=ExperimentOne'),
	    'const' => link_to('Constraints','/expershow?id=ExperimentOne'),
	    'dcol'  => link_to('DataCollection','/expershow?id=ExperimentOne'),
	    'conts' => link_to('Containers','/expershow?id=ExperimentOne'),
	    'rezs'  => link_to('Resources','/expershow?id=ExperimentOne')
          }
        ]
    elsif id == 'ExperimentTwo'
        exper = [
          { 
            'owner' => 'benzel',
	    'proj'  => 'Tutorial2013 Project',
	    'stat'  => 'Changing',
	    'topol' => link_to('Topology','/expershow?id=ExperimentTwo'),
	    'acts'  => link_to('Actions','/expershow?id=ExperimentTwo'),
	    'const' => link_to('Constraints','/expershow?id=ExperimentTwo'),
	    'dcol'  => link_to('DataCollection','/expershow?id=ExperimentTwo'),
	    'conts' => link_to('Containers','/expershow?id=ExperimentTwo'),
	    'rezs'  => link_to('Resources','/expershow?id=ExperimentTwo')
          }
        ]
    elsif id == 'ExperimentThree'
        exper = [
          { 
            'owner' => 'bfdh',
	    'proj'  => 'Super Secret Project',
	    'stat'  => 'Realizing',
	    'topol' => link_to('Topology','/expershow?id=ExperimentThree'),
	    'acts'  => link_to('Actions','/expershow?id=ExperimentThree'),
	    'const' => link_to('Constraints','/expershow?id=ExperimentThree'),
	    'dcol'  => link_to('DataCollection','/expershow?id=ExperimentThree'),
	    'conts' => link_to('Containers','/expershow?id=ExperimentThree'),
	    'rezs'  => link_to('Resources','/expershow?id=ExperimentThree')
          }
        ]
    end
    client = nil
    exper
  end

  # show = show specified experiment
  def showExperiments
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

    # for now, stub out viewExperiments
    exper = experData(params["id"])

    text = '<table><tr><td>Experiment</td><td>' + params["id"]
    owner = session[('exper_' + params["id"])]
    order = Array.new
    order = [ 'owner','proj','stat','topol','acts','const','dcol','conts','rezs' ]
    exper.each do |h|
	order.each do |k|
	    v = h[k]
	    if v.nil? or v.blank?
	        v = '&nbsp;'
	    end

	    if k == 'topol' 
    	        text = text + '<tr><td>Attributes</td><td>'
	    end
	    if k == 'owner'
    	        #text = text + ('<tr><td>Owner</td><td>' + v + '</td></tr>')
    	        text = text + ('<tr><td>Owner</td><td>' + owner + '</td></tr>')
	    elsif k == 'proj'
    	        text = text + ('<tr><td>Parent Project</td><td>' + v + '</td></tr>')
	    elsif k == 'stat'
    	        text = text + ('<tr><td>Status</td><td>' + v + '</td></tr>')
	    else
	        text = text + (v + ' ')
	        if !k.eql?('rezs')
    	            text = text + ' &bull; '
	        end
	    end

	    if k == 'rez' 
    	        text = text + '</td></tr>'
	    end
	end
    end

    client = nil

    text = text + '<tr><td><input type="button" value="Run Experiment"></td><td><input type="button" value="Halt Experiment"></td></tr>'
    text = text + '</table>'

    raw(text)
  end

  def listProjects
    text = '<table><tr><th>Project</th><th>Owner</th><th>Members</th><th>Approved</th></tr>'
    session.sort.each do |k, v|
	# skip data elements not related to projects
	next unless k.match(/^proj_/)

	# get this project ID, from which you get everything else
	projid = k[5, k.length - 5]

	# now that you have the project ID, get the related data
	exps = session[projid + '_exps']
	url = session[projid + '_url']
	affil = session[projid + '_affil']
	pdesc = session[projid + '_desc']
	membs = session[projid + '_members']
	owner = session[projid + '_owner']
	apprv = session[projid + '_approved']

	# give approved projects a gold star
	image = '&nbsp;'
	if apprv 
	    image = image_tag("gold-star.jpg", 'size' => '20x20')
	end

	#
	# deal with HTML output
	#

	# do we need a separator?
	if text.match(/\<td\>/i)
	    text = text + '<tr><td colspan="4" align="center"><hr width="75%"></td></tr>'
	end

	# create usual output
	text = text + ('<tr><td>' + projid + '</td><td>' + owner + '</td><td>' + membs + '</td><td>' + image + '</td></tr>')
	unless pdesc.blank?
	    text = text + ('<tr><td>Description</td><td colspan="3">' + pdesc + '</td></tr>')
	end
	unless affil.blank?
	    text = text + ('<tr><td>Affiliation</td><td colspan="3">' + affil + '</td></tr>')
	end
	unless url.blank?
	    text = text + ('<tr><td>URL</td><td colspan="3"><a href="' + url + '">' + url + '</a></td></tr>')
	end
	unless exps.blank?
	    text = text + ('<tr><td>Experiments</td><td colspan="3">' + exps + '</td></tr>')
	end
    end
    text = text + '</table>'
    raw(text)
  end

  def listExperiments
    text = ''
    session.sort.each do |k, v|
	next unless k.match(/^exper_/)

	owner = session[k]

	experid = k[6, k.length - 6]
	experlink = link_to(experid,'/expershow?id='+experid)
	exper = experData(experid)
	next if exper.nil?

	# this is probably incorrectly stubbed and should not be array of hashes, but rather a simple hash
	exper.each do |h|
	    next if h.nil?

            text += "<table>\n"
            text += "<tr><th width=\"100\">Experiment</th><th width=\"100\">Owner</th><th width=\"100\">Parent Project</th><th width=\"100\">Status</th></tr>\n"
	    text = text + "<tr>\n"
	    text = text + ('  <td>' + experlink + '</td>' + "\n")
	    text = text + ('  <td>' + owner + '</td>' + "\n")
	    text = text + (' <td>' + h['proj'] + '</td>' + "\n")
	    text = text + (' <td>' + h['stat'] + '</td>' + "\n")
	    text = text + ('</tr>' + "\n")
            text += "</table>\n"
        end
    end
    
    raw(text)
  end

  # nuke session state
  def clean_slate
    session[:profile] = session[:error] = session[:pwrdmgmt] = nil
    session[:pwrderror] = false
    session.each do |k, v|
        next unless k.match(/^(proj)_|(_members$)/)
	session[k] = nil
    end
    return
  end

end # module ApplicationHelper
