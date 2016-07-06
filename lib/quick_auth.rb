require "quick_auth/version"
require "quick_auth/model_base"
require "quick_auth/authentication"
require "quick_auth/authentic"
require "quick_auth/client"
require "quick_auth/token"
require "quick_auth/grant"
require "quick_auth/oauth2/endpoints"

module QuickAuth
  # Your code goes here...

  if defined?(Rails)
    class Railtie < Rails::Railtie
      initializer "quick_auth.configure" do
        config_file = Rails.root.join("config", "quick_auth.yml")
        if File.exists?(config_file)
          QuickAuth.configure(YAML.load_file(config_file)[Rails.env])
        else
          QuickAuth.configure
        end
      end
    end
  end

  class << self

    def configure(opts=nil)
      opts ||= {
        auth_methods: [:session],
        classes: {
          client: "::Client",
          token: "::Token",
          grant: "::Grant",
          user: "::User"
        }
      }
      @options = opts.with_indifferent_access
    end

    def options
      @options ||= {}
    end

    def models
      @models ||= begin
        ModelMap.new(@options[:classes])
      end
    end

  end

  module Errors

    class InvalidAccessTokenError < StandardError
    end

  end

  class ModelMap

    def initialize(classes)
      @classes = classes
    end

    def [](val)
      val = val.to_sym
      return @classes[val].constantize
    end

  end

end
