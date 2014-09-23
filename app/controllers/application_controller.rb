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

  # interpolate links into translation strings: {tag~url} -> <a href="url">tag</a>
  def add_urls(text)
    text.scan(/\{[^\}]+\}/).each do |m|
        parts = m.split('~')
	tag = parts[0]
	tag.tr! '{',''
	url_name = parts[1]
	url_name.tr! '}',''
	url = AppConfig.urls[url_name]
	href = "<a href=\"#{url}\">#{tag}</a>"
	text.sub! m,href
    end

    text.html_safe
  end
  helper_method :add_urls
end
