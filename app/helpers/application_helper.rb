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

  # check to see if you need up update the current experiment
  def saveExperiment
logger.debug '==>saveExperiment...'
    if !session.nil? && !@_current_user.blank? && !params['id'].blank?
    end
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
	    'topol' => link_to(t('experiment_show_page.topol_link_text'),'#',
	                 :onclick =>"if (hiddenFlag) return false; document.getElementById('hidden_topol').style.display='block'; hiddenFlag = true; return false;"),
	    'acts'  => link_to(t('experiment_show_page.actions_link_text'),'#',
	                 :onclick =>"if (hiddenFlag) return false; document.getElementById('hidden_actions').style.display='block'; hiddenFlag = true; return false;"),
	    'const' => link_to(t('experiment_show_page.const_link_text'),'#',
	                 :onclick =>"if (hiddenFlag) return false; document.getElementById('hidden_const').style.display='block'; hiddenFlag = true; return false;"),
	    'dcol'  => link_to(t('experiment_show_page.dc_link_text'),'#',
	                 :onclick =>"if (hiddenFlag) return false; document.getElementById('hidden_dc').style.display='block'; hiddenFlag = true; return false;"),
	    'conts' => link_to(t('experiment_show_page.cont_link_text'),'#',
	                 :onclick =>"if (hiddenFlag) return false; document.getElementById('hidden_conts').style.display='block'; hiddenFlag = true; return false;"),
	    'rezs'  => link_to(t('experiment_show_page.rez_link_text'),'#',
	                 :onclick =>"if (hiddenFlag) return false; document.getElementById('hidden_rezs').style.display='block'; hiddenFlag = true; return false;"),
          }
        ]
    elsif id == 'ExperimentTwo'
        exper = [
          { 
            'owner' => 'benzel',
	    'proj'  => 'Tutorial2013 Project',
	    'stat'  => 'Changing',
	    'topol' => link_to(t('experiment_show_page.topol_link_text'),'/expershow?id=ExperimentTwo'),
	    'acts'  => link_to(t('experiment_show_page.actions_link_text'),'/expershow?id=ExperimentTwo'),
	    'const' => link_to(t('experiment_show_page.const_link_text'),'/expershow?id=ExperimentTwo'),
	    'dcol'  => link_to(t('experiment_show_page.dc_link_text'),'/expershow?id=ExperimentTwo'),
	    'conts' => link_to(t('experiment_show_page.cont_link_text'),'/expershow?id=ExperimentTwo'),
	    'rezs'  => link_to(t('experiment_show_page.rez_link_text'),'/expershow?id=ExperimentTwo')
          }
        ]
    elsif id == 'ExperimentThree'
        exper = [
          { 
            'owner' => 'bfdh',
	    'proj'  => 'Super Secret Project',
	    'stat'  => 'Realizing',
	    'topol' => link_to(t('experiment_show_page.topol_link_text'),'/expershow?id=ExperimentThree'),
	    'acts'  => link_to(t('experiment_show_page.actions_link_text'),'/expershow?id=ExperimentThree'),
	    'const' => link_to(t('experiment_show_page.const_link_text'),'/expershow?id=ExperimentThree'),
	    'dcol'  => link_to(t('experiment_show_page.dc_link_text'),'/expershow?id=ExperimentThree'),
	    'conts' => link_to(t('experiment_show_page.cont_link_text'),'/expershow?id=ExperimentThree'),
	    'rezs'  => link_to(t('experiment_show_page.rez_link_text'),'/expershow?id=ExperimentThree')
          }
        ]
    end
    client = nil
    exper
  end

  def getUserName(uid)
      name = uid # default in case of disaster

      # first, we need a secure SOAP transaction pathway
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

      # now we need to get the user profile for this user id
      response = client.call(
	         :get_user_profile,
	         "message" => {'uid' => uid, :order! => [:uid] }
	       )
      if response.success? == true
	  # pick out the data by parsing profile tree: an array of hashes
	  a = response.to_hash[:get_user_profile_response][:return][:attributes]
          a.each do |h|
	      if h[:name] == 'name'
	          name = h[:value]
	      end
	  end
      end

      client = nil

      name
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
    order = Array.new
    order = [ 'owner','proj','stat','topol','acts','const','dcol','conts','rezs' ]
    exper.each do |h|
	order.each do |k|
	    v = h[k]
	    if v.nil? or v.blank?
	        v = '&nbsp;'
	    end

	    if k == 'topol' 
    	        text = text + '<tr><td>' + t('experiment_show_page.attributes') + '</td><td>'
	    end
	    if k == 'owner'
		owner = getUserName(v)
		if owner.nil?
		    owner = v
		end
    	        #text = text + ('<tr><td>Owner</td><td>' + v + '</td></tr>')
    	        text = text + ('<tr><td>' + t('experiment_show_page.owner') + '</td><td>' + owner + '</td></tr>')
	    elsif k == 'proj'
    	        text = text + ('<tr><td>' + t('experiment_show_page.project') + '</td><td>' + v + '</td></tr>')
	    elsif k == 'stat'
    	        text = text + ('<tr><td>' + t('experiment_show_page.status') + '</td><td>' + v + '</td></tr>')
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

    # usually-hidden areas
    text = text + '<div style="display: none;"><input type="text" name="whichaction" id="whichaction" size="25"></div>'
    list = [
        { 'title' => 'Topology', 'abbrev' => 'topol'},
        { 'title' => 'Actions', 'abbrev' => 'actions'},
        { 'title' => 'Constraints', 'abbrev' => 'const'},
        { 'title' => 'Data Collection', 'abbrev' => 'dc'},
        { 'title' => 'Containers', 'abbrev' => 'conts'},
        { 'title' => 'Resources', 'abbrev' => 'rezs'},
    ]
    list.each do |h|
	@title = h["title"]
	@id = "hidden_" + h["abbrev"]
	@idfile = "hidden_" + h["abbrev"] + "_file"
	@todo = 'download_' + h["abbrev"]
	@varname = "attrib_" + h["abbrev"]
        @hidden = <<END
    <div style="display: none;" id="#{@id}" name="#{@id}">
	<h4>#{@title}<h4>
	<textarea rows="5" cols="75" name="#{@varname}">lorem ipsum #{@title}</textarea>
	<br>
        <input type="button" value="Save"     onClick="hiddenFlag=false; document.getElementById('expershowform').submit(); return true;">
        <input type="button" value="Download" onClick="hiddenFlag=false; document.getElementById('whichaction').value='#{@todo}'; document.getElementById('expershowform').submit(); return true;">
        <input type="button" value="Replace"  onClick="document.getElementById('#{@idfile}').style.display='block'; return false;">
        <input type="button" value="Cancel"   onClick="document.getElementById('#{@id}').style.display='none'; hiddenFlag = false; return false;">
    </div>
    <div style="display: none;" id="#{@idfile}" name="#{@idfile}">
	<h5>Replace #{@title} From a File</h5>
    	<input type="file">
        <input type="button" value="Done" onClick="document.getElementById('#{@idfile}').style.display='none'; return false;">
    </div>
END
        text = text + @hidden
    end

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
	stuff = Array.new
	exper.each do |h|
	    next if h.nil?

	    stuff.clear
	    stuff.push("<table>\n", "<tr>\n")
	    stuff.push('<th width="100">', t('experiment_show_page.experiment'), "</th>\n")
	    stuff.push('<th width="100">', t('experiment_show_page.owner'),      "</th>\n")
	    stuff.push('<th width="100">', t('experiment_show_page.project'),    "</th>\n")
	    stuff.push('<th width="100">', t('experiment_show_page.status'),     "</th>\n")
	    stuff.push("</tr>\n")

	    stuff.push("<tr>\n")
	    stuff.push('<td>', experlink, '</td>', "\n")
	    stuff.push('<td>', owner,     '</td>', "\n")
	    stuff.push('<td>', h['proj'], '</td>', "\n")
	    stuff.push('<td>', h['stat'], '</td>', "\n")
	    stuff.push('</tr>',"\n")
	    stuff.push("</table>\n")

	    text = text + stuff.join(' ')
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
