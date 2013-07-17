// $Id: agua.js,v 1.2 2009/12/07 19:23:56 nomonstersinme Exp $

Drupal.behaviors.aguaBehavior = function(context) {
  /**
   * Superfish Menus
   * http://users.tpg.com.au/j_birch/plugins/superfish/
   * To use this feature please add the superfish.js to the js directory
   */
  jQuery('#navigation ul').superfish({
    animation: { opacity: 'show'},
    easing: 'swing',
    speed: 250,
    autoArrows:  false,
    dropShadows: false /* Needed for IE */
  });

  /**
   * Forum Comment Link Dialog Box
   * When clicking the link icon in forum comments,
   * this code triggers a dialog box with a link
   * to the comment for easy access to copy it.
   */
  jQuery(".copy-comment").click(function() {
      prompt('Link to this comment:', this.href);
  });


	borderSize();
	
	function borderSize(){
		var height = $('#main').height();
		if($('#sidebar-left').height() < height){
			$('#sidebar-left').css('height', height);
		}
		if($('#sidebar-right').height() < height){
			$('#sidebar-right').css('height', height);
		}
	}



};
