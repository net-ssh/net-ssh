module Net
  module SSH
    module Transport
      module Kex
        # Loads MLKEM768X25519Sha256 support backed by Ruby OpenSSL KEM APIs.
        module MLKEM768X25519Sha256Loader
          begin
            require 'net/ssh/transport/kex/mlkem768_x25519_sha256'
            Net::SSH::Transport::Kex::MLKEM768X25519Sha256.ensure_supported!
            LOADED = true
            ERROR = nil
          rescue LoadError => e
            ERROR = e
            LOADED = false
          rescue StandardError => e
            if defined?(Net::SSH::Transport::Kex::MLKEM768X25519Sha256::UnsupportedError) &&
               e.is_a?(Net::SSH::Transport::Kex::MLKEM768X25519Sha256::UnsupportedError)
              ERROR = e
              LOADED = false
            else
              raise
            end
          end

          def self.raiseUnlessLoaded(message)
            description = LOADED ? '' : mlkem768x25519SupportRequired
            description += "#{ERROR.class} : \"#{ERROR.message}\"\n" if ERROR
            raise NotImplementedError, "#{message}\n#{description}" unless LOADED
          end

          def self.mlkem768x25519SupportRequired
            "net-ssh requires openssl >= 4.0.0 and OpenSSL >= 3.5.0 " \
              "with ML-KEM-768 and X25519 enabled for mlkem768x25519-sha256 support.\n"
          end
        end
      end
    end
  end
end
