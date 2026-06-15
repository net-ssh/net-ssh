module Net
  module SSH
    module Transport
      # Loads chacha20-poly1305 support backed by Ruby OpenSSL APIs.
      module ChaCha20Poly1305CipherLoader
        begin
          require 'net/ssh/transport/chacha20_poly1305_cipher'
          Net::SSH::Transport::ChaCha20Poly1305Cipher.ensure_supported!
          LOADED = true
          ERROR = nil
        rescue LoadError => e
          ERROR = e
          LOADED = false
        rescue StandardError => e
          if defined?(Net::SSH::Transport::ChaCha20Poly1305Cipher::UnsupportedError) &&
             e.is_a?(Net::SSH::Transport::ChaCha20Poly1305Cipher::UnsupportedError)
            ERROR = e
            LOADED = false
          else
            raise
          end
        end

        def self.raiseUnlessLoaded(message)
          description = LOADED ? '' : chacha20_poly1305_support_required
          description += "#{ERROR.class} : \"#{ERROR.message}\"\n" if ERROR
          raise NotImplementedError, "#{message}\n#{description}" unless LOADED
        end

        def self.chacha20_poly1305_support_required
          "net-ssh requires openssl >= 3.2.0 and a crypto backend with ChaCha20 and Poly1305 enabled for chacha20-poly1305@openssh.com support.\n"
        end
      end
    end
  end
end
