
module QuickAuth
  module ActiveRecord
    module Authentic
      extend ActiveSupport::Concern

      module ClassMethods
        def find_using_perishable_token(token)
          u = self.where(perishable_token: token).where("perishable_token_expires_at > ?", Time.now).first
        end

        def quick_auth_authentic!(opts={})
          if respond_to?(:field)
            field :password_digest, type: String
            if opts[:persistent_token]
              field :persistent_token, type: String
            end
            if opts[:perishable_token]
              field :perishable_token, type: String
              field :perishable_token_expires_at, type: Time
            end
          end
        end

        def friendly_token
          # use base64url as defined by RFC4648
          SecureRandom.base64(15).tr('+/=', '').strip.delete("\n")
        end

      end

    
      def authenticated?(pw)
        return true if password_digest.present? && BCrypt::Password.new(password_digest).is_password?(pw)
        return true if respond_to?(:persistent_token) && self.persistent_token.present? && (self.persistent_token == pw)
        return true if respond_to?(:perishable_token) && self.perishable_token_valid? && (self.perishable_token == pw)
        return false
      end
      
      def password
        @password
      end
      
      def password=(value)
        if value.present?
          @password = value
          self.password_digest = BCrypt::Password.create(value)
        else
          @password = nil
          self.password_digest = nil
        end
      end
      
      def password_required?
        password_digest.blank?
      end

      def perishable_token_valid?
        self.perishable_token.present? && !self.perishable_token_expires_at.nil? && (self.perishable_token_expires_at > Time.now)
      end
      
      def reset_perishable_token!
        self.perishable_token_expires_at = 1.day.from_now
        self.perishable_token = self.class.friendly_token
        self.save
      end

    end
  end
end