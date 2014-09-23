// analytics.js -- app-specific javascript

// function which checks to see of the 0th page of the New Projects set is good to go
function np0ok()  {
    var rc = 0;

    if (document.getElementById("cb1").checked == true) {
    	rc += 1;
    }
    if (document.getElementById("cb2").checked == true) {
    	rc += 1;
    }


    // did they check both boxes? If so, proceed
    if (rc == 2) {
        return true;
    } else {
	alert(I18n["np0_checks"]);
        return false;
    }
}
// eof
