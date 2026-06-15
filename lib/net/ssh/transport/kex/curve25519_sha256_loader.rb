module Net
  module SSH
    module Transport
      module Kex
        # Loads Curve25519Sha256 support backed by Ruby OpenSSL X25519 APIs.
        module Curve25519Sha256Loader
          begin
            require 'net/ssh/transport/kex/curve25519_sha256'
            Net::SSH::Transport::Kex::Curve25519Sha256.ensure_supported!
            LOADED = true
            ERROR = nil
          rescue LoadError => e
            ERROR = e
            LOADED = false
          rescue StandardError => e
            if defined?(Net::SSH::Transport::Kex::Curve25519Sha256::UnsupportedError) &&
               e.is_a?(Net::SSH::Transport::Kex::Curve25519Sha256::UnsupportedError)
              ERROR = e
              LOADED = false
            else
              raise
            end
          end

          def self.raiseUnlessLoaded(message)
            description = LOADED ? '' : x25519SupportRequired
            description += "#{ERROR.class} : \"#{ERROR.message}\"\n" if ERROR
            raise NotImplementedError, "#{message}\n#{description}" unless LOADED
          end

          def self.x25519SupportRequired
            "net-ssh requires openssl >= 3.2.0 and a crypto backend with X25519 enabled for curve25519-sha256 support.\n"
          end
        end
      end
    end
  end
end
