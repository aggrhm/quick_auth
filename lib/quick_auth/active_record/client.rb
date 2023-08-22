module QuickAuth

  module ActiveRecord

    module Client

      def self.included(base)
        base.send :extend, ClassMethods
      end

      module ClassMethods

        def quick_auth_client!(opts={})
          @quick_auth_orm = :active_record
          if respond_to?(:field)
            field :uuid, type: String, index: true
            field :name, type: String
            field :secret, type: String
            field :redirect_uri, type: String
            field :access_token_expires_in, type: Integer, default: 3600
            timestamps!
          end
          quick_auth_client_scopes!
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

end
