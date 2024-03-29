module QuickAuth

  module ActiveRecord

    module Grant

      def self.included(base)
        base.send :extend, ClassMethods
      end

      module ClassMethods

        def quick_auth_grant!(opts={})
          @quick_auth_orm = :schema_sync
          if respond_to?(:field)
            field :resource_owner_id, type: String, index: true
            field :client_id, type: String, index: true
            field :code, type: String
            field :scope, type: String
            timestamps!
          end

          scope :with_client, lambda {|cid|
            where(client_id: cid)
          }
          scope :with_resource_owner, lambda {|roid|
            where(resource_owner_id: roid)
          }
          scope :with_code, lambda {|c|
            where(code: c)
          }
          scope :expired, lambda {
            where("created_at < ?", 10.minutes.ago)
          }
          scope :not_expired, lambda {
            where("created_at > ?", 10.minutes.ago)
          }
        end

        def generate(client, user, opts={})
          g = self.new
          g.client_id = client.uuid
          g.resource_owner_id = user.id.to_s
          g.scope = opts[:scope]
          g.code = SecureRandom.hex(16)
          g.save

          self.clean_grants(client, user)
          return g
        end

        def clean_grants(client, user)
          self.with_client(client.uuid).with_resource_owner(user.id).expired.delete_all
        end

        def find_with_code_for_client(client, code)
          return self.with_client(client.uuid).with_code(code).not_expired.first
        end

      end

      ## MEMBER METHODS

      def expired?
        self.created_at < 10.minutes.ago
      end

      def user
        @user ||= QuickAuth.models[:user].find(self.resource_owner_id)
      end

      def client
        @client ||= QuickAuth.models[:client].find_with_uuid(self.client_id)
      end

      def to_api
        ret = {}
        ret[:code] = self.code
        ret[:scope] = self.scope
        return ret
      end

    end

  end

end
