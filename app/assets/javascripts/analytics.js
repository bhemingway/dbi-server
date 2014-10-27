// analytics.js -- app-specific javascript

/* To initialize BS3 tooltips set this below */
$(function () { 
    $("[data-toggle='tooltip']").tooltip(); 
});;
/* To initialize BS3 popovers set this below */
$(function () { 
    $("[data-toggle='popover']").popover(); 
});

// function which does the appropriate validation, if any, onload for body tag
function check_onload() {
    if ($("#login_newproject").length) {
	return np0ok();
    }
    if ($("#login_newproject1").length) {
	return np1ok();
    }
    if ($("#login_newproject2").length) {
	return np2ok();
    }
    if ($("#login_newproject3").length) {
	return np3ok();
    }
    return true;
}

// function which submits to the previous form if going backwards
function submitto(url) {
    var myurl = window.location.href;
    alert('starting at ' + myurl + ' submitting to ' + url);
    window.location.href = url;
    //$.get(url);
    //return true;
}

// function which does the canceling if the user cancels
function cancel() {
    location.href = "/login";
    return false;
}

// function which checks to see if the 0th page of the New Projects set is good to go
function np0ok()  {
    var msgs = [];
    var div = document.getElementById("next_button_div_0");
    var button = document.getElementById("next_button_0");

    // check the form elements for completeness
    if (document.getElementById("f_cb1").checked == false) {
        msgs.push(I18n['p0_cb1_err']);
    }

    if (document.getElementById("f_cb2").checked == false) {
        msgs.push(I18n['p0_cb2_err']);
    }

    // are there errors? then report them otherwise clear the form to go forward
    if (msgs.length > 0) {
        //div.title = I18n['newproject.form.error_title'];
        //div.content = msgs.join("\n");
        div.title = msgs.join("\n");
        button.disabled = true;
    } else {
        div.title = '';
        div.content = ''
        button.disabled = false;
    }

    return true; // always Ok
}

// function which checks to see if the 1st page of the New Projects set is good to go
function np1ok()  {
    var rc = 0;

    // start with a clean slate
    document.getElementById("next_button_div_1").title = '';
    document.getElementById("next_button_1").disabled = true;

    // check the form elements for completeness
    if (document.getElementById("f_usage_type_leader").checked) {
    	rc += 1;
    }
    if (document.getElementById("f_usage_type_member").checked) {
    	rc += 1;
    }
    if (document.getElementById("f_usage_type_academic").checked) {
    	rc += 1;
    }
    if (document.getElementById("f_usage_type_student").checked) {
    	rc += 1;
    }
    if (document.getElementById("f_usage_type_staff").checked) {
    	rc += 1;
    }

    // did they pick an opton? 
    if (rc == 1) {
        document.getElementById("next_button_1").disabled = false;
    } else {
        document.getElementById("next_button_div_1").title = I18n['p1_usage_type_err'] + '\n';
    }

    return true; // always Ok
}

// function which checks to see if a text value is present
function no_text(value) {
    if (value == null || value == '') {
	return true;
    } else {
    	return false;
    }
}

// function which checks to see if the 2nd page of the New Projects set is good to go
function np2ok()  {
    var msgs = [];

    // start with a clean slate
    document.getElementById("next_button_div_2").title = '';
    document.getElementById("next_button_2").disabled = true;

    // check the form elements for completeness
    if (no_text(document.getElementById("f_name").value)) {
        msgs.push(I18n['p2_name_err']);
    }
    if (no_text(document.getElementById("f_email").value)) {
        msgs.push(I18n['p2_email_err']);
    }
    if (no_text(document.getElementById("f_telno").value)) {
        msgs.push(I18n['p2_telno_err']);
    }
    if (no_text(document.getElementById("f_job").value)) {
        msgs.push(I18n['p2_job_err']);
    }
    if (no_text(document.getElementById("f_org_name").value)) {
        msgs.push(I18n['p2_org_name_err']);
    }
    if (no_text(document.getElementById("f_org_abbrev").value)) {
        msgs.push(I18n['p2_org_abbrev_err']);
    }
    if (no_text(document.getElementById("f_org_url").value)) {
        msgs.push(I18n['p2_org_url_err']);
    }
    if (no_text(document.getElementById("f_addr1").value)) {
        msgs.push(I18n['p2_addr1_err']);
    }
    if (no_text(document.getElementById("f_addr2").value)) {
        msgs.push(I18n['p2_addr2_err']);
    }
    if (no_text(document.getElementById("f_city").value)) {
        msgs.push(I18n['p2_city_err']);
    }
    if (no_text(document.getElementById("f_zip").value)) {
        msgs.push(I18n['p2_zip_err']);
    }
    if (no_text(document.getElementById("f_country").value)) {
        msgs.push(I18n['p2_country_err']);
    }
    if (no_text(document.getElementById("f_user_name").value)) {
        msgs.push(I18n['p2_user_name_err']);
    }
/*
could not validate password in Javascript because rails gives me nil in all cases
    if (no_text(document.getElementById("f_password1").value)) {
        msgs.push(I18n['p2_password1_err']);
    }
    if (no_text(document.getElementById("f_password2").value)) {
        msgs.push(I18n['p2_password2_err']);
    }
    if (document.getElementById("f_password2").value != document.getElementById("f_password2").value) {
        msgs.push(I18n['p2_password_mismatch_err']);
    }
*/

    // did their input generate any errors? then complain else proceed
    if (msgs.length > 0) {
        document.getElementById("next_button_div_2").title = msgs.join("\n");
    } else {
        document.getElementById("next_button_2").disabled = false;
    }

    return true; // always Ok
}

// function which checks to see if the 3rd page of the New Projects set is good to go
function np3ok()  {
    var msgs = [];

    // start with a clean slate
    document.getElementById("next_button_div_3").title = '';
    document.getElementById("next_button_3").disabled = true;

    // check the form elements for completeness
    if (no_text(document.getElementById("f_proj_name").value)) {
        msgs.push(I18n['p3_proj_name_err']);
    }
    if (no_text(document.getElementById("f_proj_plan").value)) {
        msgs.push(I18n['p3_proj_plan_err']);
    }
    if (no_text(document.getElementById("f_proj_url").value)) {
        msgs.push(I18n['p3_proj_url_err']);
    }
    if (no_text(document.getElementById("f_proj_org_type").value) || document.getElementById("f_proj_org_type").value == 'AAAA') {
        msgs.push(I18n['p3_proj_org_type_err']);
    }
    if (no_text(document.getElementById("f_proj_res_focus").value) || document.getElementById("f_proj_res_focus").value == 'AAAA') {
        msgs.push(I18n['p3_proj_res_focus_err']);
    }
    if (no_text(document.getElementById("f_proj_funding").value) || document.getElementById("f_proj_funding").value == 'AAAA') {
        msgs.push(I18n['p3_proj_funding_err']);
    }
    if (no_text(document.getElementById("f_proj_listing").value)) {
        msgs.push(I18n['p3_proj_listing_err']);
    }

    // did their input generate any errors? then complain else proceed
    if (msgs.length > 0) {
        document.getElementById("next_button_div_3").title = msgs.join("\n");
    } else {
        document.getElementById("next_button_3").disabled = false;
    }

    return true; // always Ok
}
// eof
