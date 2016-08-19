class ApplicationController < ActionController::Base

  before_filter :store_current_location, :unless => :devise_controller?

  include Pundit
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized

  private

  def store_current_location
    store_location_for(:user, request.url)
  end

  def user_not_authorized(exception)
    policy_name = exception.policy.class.to_s.underscore

    flash[:alert] = I18n.t "pundit.#{policy_name}.#{exception.query}", default: 'Please sign in to view the calendar page'
    redirect_to(request.referrer || new_user_session_path)
  end

end
