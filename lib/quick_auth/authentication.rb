module QuickAuth
  module Authentication

  protected
    # Inclusion hook to make #current_user and #signed_in?
    # available as ActionView helper methods.

    class << self
      def included(base)
        base.send :helper_method, :current_user, :signed_in? if base.respond_to? :helper_method
      end
    end
    
    # Returns true or false if the user is signed in.
    # Preloads @current_user with the user model if they're signed in.
    def signed_in?
      !!current_user
    end
    
    # Accesses the current user from the session.
    # Future calls avoid the database because nil is not equal to false.
    def current_user
      if @current_user.nil? && QuickAuth.options[:auth_methods].include?(:session)
        sign_in_from_session
      end
      if @current_user.nil? && current_token
        @current_user = current_token.user
      end
      @current_user
    end

    def current_client
      if @current_client.nil? && current_token
        @current_client = current_token.client
      end
      @current_client
    end

    def current_token
      if @current_token.nil? && QuickAuth.options[:auth_methods].include?(:token)
        sign_in_from_token
      end
      @current_token
    end
    
    # Store the given user id in the session.
    def current_user=(new_user)
      session[:user_id] = new_user ? new_user.id.to_s : nil
      @current_user = new_user || false
    end

    # Redirect as appropriate when an access request fails.
    #
    # The default action is to redirect to the sign_in screen.
    #
    # Override this method in your controllers if you want to have special
    # behavior in case the user is not authorized
    # to access the requested action. For example, a popup window might
    # simply close itself.
    def access_denied
      respond_to do |format|
        format.html do
          store_location
          redirect_to new_session_path
        end
        # format.any doesn't work in rails version < http://dev.rubyonrails.org/changeset/8987
        # you may want to change format.any to e.g. format.any(:js, :xml)
        format.any do
          request_http_basic_authentication 'Web Password'
        end
      end
    end

    # Store the URI of the current request in the session.
    #
    # We can return to this location by calling #redirect_back_or_default.
    def store_location
      session[:return_to] = request.request_uri
    end

    # Redirect to the URI stored by the most recent store_location call or
    # to the passed default. Set an appropriately modified
    # after_filter :store_location, :only => [:index, :new, :show, :edit]
    # for any controller you want to be bounce-backable.
    def redirect_back_or_default(default)
      redirect_to(session[:return_to] || default)
      session[:return_to] = nil
    end
    
    # Called from #current_user. First attempt to sign_in by the user id stored in the session.
    def sign_in_from_session
      if session[:user_id]
        self.current_user = User.find(session[:user_id])
      end
    end

    # Called from #current_user. Now, attempt to sign_in by basic authentication information.
    def sign_in_from_basic_auth
      authenticate_with_http_basic do |email, password|
        self.current_user = User.authenticate(email, password)
      end
    end

    def sign_in_from_token
      auth_header = request.headers["Authorization"]
      return if auth_header.nil?
      aps = auth_header.split(/\s/)
      return if aps.first != "Bearer"
      token = QuickAuth.models[:token].find_with_valid_access_token(aps.last)
      raise QuickAuth::Errors::InvalidAccessTokenError if token.nil?
      @current_token = token
    end
    
    # This is ususally what you want; resetting the session willy-nilly wreaks
    # havoc with forgery protection, and is only strictly necessary on sign_in.
    # However, **all session state variables should be unset here**.
    def sign_out_keeping_session!
      # Kill server-side auth cookie
      @current_user = nil # not signed in, and don't do it for me
      @current_token = nil
      @current_client = nil
      session[:user_id] = nil # keeps the session but kill our variable
      # explicitly kill any other session variables you set
    end

    # The session should only be reset at the tail end of a form POST --
    # otherwise the request forgery protection fails. It's only really necessary
    # when you cross quarantine (signed-out to signed-in).
    def sign_out_killing_session!
      sign_out_keeping_session!
      reset_session
    end
  end
end
