module QuickAuth

  module Token
    include QuickAuth::ModelBase

    def self.included(base)
      base.send :extend, ClassMethods
    end

    module ClassMethods

      def quick_auth_token!(opts={})
        case QuickAuth.orm_for_model(self)
        when :mongoid
          quick_auth_token_mongoid_fields!
        when :active_record
          quick_auth_token_active_record_fields!
        end
      end

      def quick_auth_token_fields_for(db)
        Rails.logger.info "NOTE: This method is deprecated, use quick_auth_token!"
        quick_auth_token_mongoid_fields!
      end

      def quick_auth_token_mongoid_fields!
        @quick_auth_orm = :mongoid
        field :roid, as: :resource_owner_id, type: String
        field :cid, as: :client_id, type: String
        field :at, as: :access_token, type: String
        field :rt, as: :refresh_token, type: String
        field :ex_at, as: :expires_at, type: Time
        field :sc, as: :scope, type: String

        include Mongoid::Timestamps::Short

        scope :with_access_token, lambda {|at|
          where(at: at)
        }
        scope :with_refresh_token, lambda {|rt|
          where(rt: rt)
        }
        scope :not_expired, lambda {
          where(:ex_at => {'$gt' => Time.now})
        }
        scope :with_client, lambda {|cid|
          where(cid: cid)
        }
        scope :with_resource_owner, lambda {|roid|
          where(roid: roid.to_s)
        }
        scope :oldest_first, lambda {
          asc(:c_at)
        }
      end

      def quick_auth_token_active_record_fields!
        @quick_auth_orm = :schema_sync
        if respond_to?(:field)
          field :resource_owner_id, type: String
          field :client_id, type: String
          field :access_token, type: String
          field :refresh_token, type: String
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
        token.report_event('generated')

        self.clean_tokens(client, user)
        return token
      end

      def refresh_access_token(client, rt)
        token = self.with_client(client.uuid).with_refresh_token(rt).first
        return nil if token.nil?
        token.refresh_access_token!(expires_in: client.access_token_expires_in)
        token.report_event('refreshed')
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
          tokens = scp.oldest_first.limit(count - 30).delete_all
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

    def to_api
      ret = {}
      ret[:access_token] = self.access_token
      ret[:token_type] = "bearer"
      ret[:expires_in] = (self.expires_at - Time.now).to_i
      ret[:refresh_token] = self.refresh_token
      ret[:scope] = self.scope
      return ret
    end

  end

end
