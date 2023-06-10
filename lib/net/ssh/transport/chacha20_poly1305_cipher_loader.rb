module Net
  module SSH
    module Transport
      # Loads chacha20 poly1305 support which requires optinal dependency rbnacl
      module ChaCha20Poly1305CipherLoader
        begin
          require 'net/ssh/transport/chacha20_poly1305_cipher'
          LOADED = true
          ERROR = nil
        rescue LoadError => e
          ERROR = e
          LOADED = false
        end
      end
    end
  end
end
