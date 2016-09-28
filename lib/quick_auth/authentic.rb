require 'digest/sha1'

module QuickAuth
  module Authentic
    extend ActiveSupport::Concern

    RegEmailName = '[\w\.%\+\-]+'
    RegDomainHead = '(?:[A-Z0-9\-]+\.)+'
    RegDomainTLD = '(?:[A-Z]{2}|com|org|edu|net|gov|mil|biz|info|mobi|name|aero|jobs|museum)'
    RegEmailOk = /\A#{RegEmailName}@#{RegDomainHead}#{RegDomainTLD}\z/i
    PasswordRequired = Proc.new { |u| u.password_required? }

    included do
      #validates_length_of :em, :within => 6..100
      #validates_format_of :em, :with => RegEmailOk
      #validates_presence_of :password, :if => PasswordRequired
      #validates_confirmation_of :password, :if => PasswordRequired, :allow_nil => true
      #validates_length_of :password, :minimum => 6, :if => PasswordRequired, :allow_nil => false, :message => "Your password must be at least 6 characters"
    end

    module ClassMethods
      def find_using_perishable_token(token)
        if @quick_auth_orm == :mongoid
          u = self.where(:phtk => token, :phtke => {'$gt' => Time.now}).first
        else
          u = self.where(perishable_token: token).where("perishable_token_exp > ?", Time.now).first
        end
      end

      def quick_auth_authentic!(opts={})
        orm = QuickAuth.orm_for_model(self)
        case orm
        when :mongoid
          quick_auth_authentic_mongoid_fields!
        when :active_record
          quick_auth_authentic_active_record_fields!
        end
      end

      def quick_auth_authentic_mongoid_fields!
        @quick_auth_orm = :mongoid
        field :crp, as: :crypted_password, type: String    # crypted password
        field :pws, as: :password_salt, type: String    # password salt
        field :pstk, as: :persistent_token, type: String    # persistant token
        field :phtk, as: :perishable_token, type: String    # perishable token
        field :phtke, as: :perishable_token_exp, type: Time      # perishable token expiration
      end
      def quick_auth_mongoid_keys!
        Rails.logger.info "NOTE: This method is deprecated. Please use authentic_mongoid_fields!"
        authentic_mongoid_fields!
      end

      def quick_auth_authentic_active_record_fields!
        @quick_auth_orm = :active_record
        if respond_to?(:field)
          field :crypted_password, type: String
          field :password_salt, type: String
          field :persistent_token, type: String
          field :perishable_token, type: String
          field :perishable_token_exp, type: Time
        end
      end

      def digest(password, salt)
        dig = [password, salt].flatten.join('')
        20.times { dig = Digest::SHA512.hexdigest(dig) }
        dig
      end

      def friendly_token
        # use base64url as defined by RFC4648
        SecureRandom.base64(15).tr('+/=', '').strip.delete("\n")
      end

    end

  
    def authenticated?(pw)
      return true if self.crypted_password == self.class.digest(pw, self.password_salt)
      return true if self.persistent_token.present? && (self.persistent_token == pw)
      return true if self.perishable_token_valid? && (self.perishable_token == pw)
      return false
    end
    
    def password
      @password
    end
    
    def password=(value)
      if value.present?
        @password = value
        self.password_salt = self.class.friendly_token
        self.crypted_password = self.class.digest(value, self.password_salt)
      end
    end
    
    def password_required?
      crypted_password.blank?
    end

    def perishable_token_valid?
      !self.perishable_token.blank? && !self.perishable_token_exp.nil? && (self.perishable_token_exp > Time.now)
    end
    
    def reset_perishable_token!
      self.perishable_token_exp = 1.day.from_now
      self.perishable_token = self.class.friendly_token
      self.save
    end

  end

end
