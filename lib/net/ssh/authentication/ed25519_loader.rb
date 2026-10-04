module Net
  module SSH
    module Authentication
      # Loads ED25519 support backed by Ruby OpenSSL raw key APIs.
      module ED25519Loader
        begin
          require 'net/ssh/authentication/ed25519'
          Net::SSH::Authentication::ED25519.ensure_supported!
          LOADED = true
          ERROR = nil
        rescue LoadError => e
          ERROR = e
          LOADED = false
        rescue StandardError => e
          if defined?(Net::SSH::Authentication::ED25519::UnsupportedError) &&
             e.is_a?(Net::SSH::Authentication::ED25519::UnsupportedError)
            ERROR = e
            LOADED = false
          else
            raise
          end
        end

        def self.raiseUnlessLoaded(message)
          description = LOADED ? '' : ed25519SupportRequired
          description += "#{ERROR.class} : \"#{ERROR.message}\"\n" if ERROR
          raise NotImplementedError, "#{message}\n#{description}" unless LOADED
        end

        def self.ed25519SupportRequired
          "net-ssh requires openssl >= 3.2.0 and a crypto backend with Ed25519 enabled for ed25519 support.\n"
        end
      end
    end
  end
end
