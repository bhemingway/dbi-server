class ApplicationController < ActionController::Base
  protect_from_forgery

  # Wed Jul 17 14:14:43 UTC 2013 BFH to support logging in, from
  # http://guides.rubyonrails.org/action_controller_overview.html#session
  private
 
  # Finds the User with the ID stored in the session with the key
  # :current_user_id This is a common way to handle user login in
  # a Rails application; logging in sets the session value and
  # logging out removes it.
  def current_user
    @_current_user ||= session[:current_user_id] &&
      User.find_by_id(session[:current_user_id])
  end
end
