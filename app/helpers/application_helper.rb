module ApplicationHelper
  # are we logged in or not? return a human-readable string to that effect
  def loginstatus
    a = 'You Are'
    b = ''
    c = t('rightgutter.loggedin');

    b = 'Not' if (@current_user.nil? or @current_user.length == 0)

    [a,b,c].join(' ').squeeze(' ')
  end
end
