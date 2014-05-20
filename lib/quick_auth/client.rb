module QuickAuth

  module Client

    def self.included(base)
      base.send :extend, ClassMethods
    end

    module ClassMethods

      def quick_auth_client_fields_for(db)
        if db == :mongoid
          field :uuid, type: String
          field :nm, as: :name, type: String
          field :sc, as: :secret, type: String
          field :ru, as: :redirect_uri, type: String

          include Mongoid::Timestamps::Short

          scope :with_uuid, lambda {|u|
            where(uuid: u)
          }
        end
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
        self.find(uuid) || self.with_uuid(uuid).first
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
