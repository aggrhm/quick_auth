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
      validates_confirmation_of :password, :if => PasswordRequired, :allow_nil => true
      validates_length_of :password, :minimum => 6, :if => PasswordRequired, :allow_nil => false
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

    module ClassMethods
      def find_using_perishable_token(token)
        u = self.first(:conditions => {:phtk => token, :phtke.gt => Time.now})
      end

			def quick_auth_mongo_keys!
				key :crp,   String    # crypted password
				key :pws,   String    # password salt
				key :pstk,  String    # persistant token
				key :phtk,  String    # perishable token
				key :phtke, Time      # perishable token expiration
						
				attr_alias :crypted_password,   :crp
				attr_alias :password_salt,      :pws
				attr_alias :persistent_token,   :pstk
				attr_alias :perishable_token,   :phtk
				attr_alias :perishable_token_exp, :phtke
			end
    end

    module InstanceMethods
    
      def authenticated?(pw)
        self.crypted_password == digest(pw, self.password_salt) ? true : false
      end
      
      def password
        @password
      end
      
      def password=(value)
        if value.present?
          @password = value
          self.password_salt = friendly_token
          self.crypted_password = digest(value, self.password_salt)
        end
      end
      
      def password_required?
        crypted_password.blank?
      end
      
      def reset_perishable_token!
        self.perishable_token_exp = 1.day.from_now
        self.perishable_token = self.friendly_token
        save!
      end

    end
  
  end
end
