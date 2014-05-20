module QuickAuth

  module OAuth2

    module Endpoints

      def self.included(base)
        base.before_filter :authenticate_client
        base.rescue_from AuthError do |e|
          render :json => e.data.to_json, :status => 400
        end
      end

      def token
        @grant_type = params[:grant_type].to_s
        case @grant_type
        when "password"
          handle_password_grant_token_request
        when "refresh_token"
          handle_refresh_token_request
        end
      end

      private

      def authenticate_client
        @client = QuickAuth.models[:client].authenticate(params[:client_id], params[:client_secret])
        if @client.nil?
          render_error error: 'invalid_client'
        end
      end

      def handle_password_grant_token_request
        username = params[:username]
        password = params[:password]
        scope = params[:scope]
        @user = QuickAuth.models[:user].authenticate(username, password)
        if @user
          @token = QuickAuth.models[:token].generate(@client, @user, {scope: scope})
          render_token(@token)
        else
          render_error error: 'invalid_grant'
        end
      end

      def handle_refresh_token_request
        refresh = params[:refresh_token]
        @token = QuickAuth.models[:token].refresh_access_token(refresh)
        if @token
          render_token(@token)
        else
          render_error error: 'invalid_grant'
        end
      end

      def render_token(token)
        render :json => token.to_api
      end

      def render_error(opts)
        raise AuthError.new(opts)
      end

    end

    class AuthError < Exception
      attr_accessor :data
      def initialize(opts)
        @data = opts
      end
    end

  end

end