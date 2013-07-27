class LoginController < ApplicationController
  def new
    session[:deterLoginStatus] = '(new)'
    render :index
  end
  def create
    session[:deterLoginStatus] = '(create)'
    render :index
  end
  def destroy
    @_current_user = session[:current_user_id] = nil
    reset_session
    session[:deterLoginStatus] = 'Logged out'
    #render :index
  end
end
