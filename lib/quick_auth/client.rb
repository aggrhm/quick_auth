module QuickAuth

  module Client

    def self.included(base)
      base.send :extend, ClassMethods
    end

    module ClassMethods

      def quick_auth_client!(opts)
        if opts[:for] == :mongoid
          quick_auth_client_mongoid_fields!
        elsif opts[:for] == :schema_sync
          quick_auth_client_schema_sync_fields!
        end
        quick_auth_client_scopes!
      end

      def quick_auth_client_fields_for(db)
        Rails.logger.info "NOTE: This method is deprecated, use quick_auth_client!"
        quick_auth_client_mongoid_fields!
      end

      def quick_auth_client_mongoid_fields!
        @quick_auth_orm = :mongoid
        field :uuid, type: String
        field :nm, as: :name, type: String
        field :sc, as: :secret, type: String
        field :ru, as: :redirect_uri, type: String
        field :ate, as: :access_token_expires_in, type: Integer, default: 3600

        include Mongoid::Timestamps::Short
      end

      def quick_auth_client_schema_sync_fields!
        @quick_auth_orm = :active_record
        field :uuid, type: String
        field :name, type: String
        field :secret, type: String
        field :redirect_uri, type: String
        field :access_token_expires_in, type: Integer, default: 3600
        timestamps!
      end

      def quick_auth_client_scopes!
        scope :with_uuid, lambda {|u|
          where(uuid: u)
        }
      end

      def register(name)
        client = self.new
        client.uuid = SecureRandom.uuid
        client.secret = SecureRandom.hex(16)
        client.name = name
        client.save
        return client
      end

      def find_with_uuid(uuid)
        self.with_uuid(uuid).first || self.find(uuid)
      end

      def authenticate(id, secret)
        client = self.find_with_uuid(id)
        if client && client.secret == secret
          return client
        else
          return nil
        end
      end

    end   ## END CLASSMETHODS

  end

end
