module QuickAuth

  module ActiveRecord

    module Token

      def self.included(base)
        base.send :extend, ClassMethods
      end

      module ClassMethods

        def quick_auth_token!(opts={})
          @quick_auth_orm = :schema_sync
          if respond_to?(:field)
            field :resource_owner_id, type: String, index: true
            field :client_id, type: String, index: true
            field :access_token, type: String, index: true
            field :refresh_token, type: String, index: true
            field :expires_at, type: Time
            field :scope, type: String
            timestamps!
          end

          scope :with_access_token, lambda {|at|
            where(access_token: at)
          }
          scope :with_refresh_token, lambda {|rt|
            where(refresh_token: rt)
          }
          scope :not_expired, lambda {
            where("expires_at > ?", Time.now)
          }
          scope :with_client, lambda {|cid|
            where(client_id: cid)
          }
          scope :with_resource_owner, lambda {|roid|
            where(resource_owner_id: roid.to_s)
          }
          scope :oldest_first, lambda {
            order(:created_at)
          }
        end

        def generate(client, user, opts={})
          token = self.new
          token.client_id = client.uuid
          token.resource_owner_id = user.id.to_s
          token.scope = opts[:scope]
          token.refresh_token = SecureRandom.hex(16)
          token.refresh_access_token!(expires_in: client.access_token_expires_in)
          token.save
          #token.report_event('generated')

          self.clean_tokens(client, user)
          return token
        end

        def refresh_access_token(client, rt)
          token = self.with_client(client.uuid).with_refresh_token(rt).first
          return nil if token.nil?
          token.refresh_access_token!(expires_in: client.access_token_expires_in)
          #token.report_event('refreshed')
          return token
        end

        def generate_token
          SecureRandom.hex(16)
        end

        def find_with_valid_access_token(at)
          token = self.with_access_token(at).not_expired.first
          token && token.access_token_valid? ? token : nil
        end

        def clean_tokens(client, user)
          # only keep 20 tokens for each client user pair
          scp = self.with_client(client.uuid).with_resource_owner(user.id)
          if (count=scp.count) > 30
            scp.oldest_first.limit(count - 30).each do |t|
              t.delete
            end
          end
        end

      end ## END CLASSMETHODS

      def access_token_valid?
        self.expires_at > Time.now
      end

      def refresh_access_token!(opts={})
        exp_in = opts[:expires_in] || 3600
        # only refresh token if about to expire
        self.reload unless self.new_record?   # make sure using latest token
        if self.expires_at.nil? || (self.expires_at - Time.now) < 10
          self.access_token = self.class.generate_token
          #self.refresh_token = self.class.generate_token
          self.expires_at = Time.now + exp_in
          self.save
        end
        self.access_token
      end

      def user
        @user ||= QuickAuth.models[:user].find(self.resource_owner_id)
      end

      def client
        @client ||= QuickAuth.models[:client].find_with_uuid(self.client_id)
      end

      def to_api(opts={})
        ret = {}
        ret[:access_token] = self.access_token
        ret[:token_type] = "bearer"
        ret[:expires_in] = (self.expires_at - Time.now).to_i
        ret[:expires_at] = self.expires_at.try(:iso8601)
        ret[:created_at] = self.created_at.try(:iso8601)
        ret[:refresh_token] = self.refresh_token
        ret[:scope] = self.scope
        return ret
      end

    end

  end

end
