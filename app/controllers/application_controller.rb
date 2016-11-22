class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_action :authenticate_user


  def authenticate_user
    client_id = ENV['K0CYSKFTQFIIMKVECEHWQ1XZNNJZ5I55HR5D0U2RI1NCDJDU']
    redirect_uri = CGI.escape("http://localhost:3000/auth")
    foursquare_url = "https://foursquare.com/oauth2/authenticate?client_id=#{client_id}&response_type=code&redirect_uri=#{redirect_uri}"
    redirect_to foursquare_url unless logged_in?
  end

  private
    def logged_in?
      !!session[:token]
    end
end
