require 'openssl'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex/abstract5656'

module Net
  module SSH
    module Transport
      module Kex
        # A key-exchange service implementing the "curve25519-sha256@libssh.org"
        # key-exchange algorithm. (defined in https://tools.ietf.org/html/draft-ietf-curdle-ssh-curves-06)
        class Curve25519Sha256 < Abstract5656
          ALGORITHM = "X25519"
          KEY_BYTES = 32

          class UnsupportedError < StandardError; end

          def self.ensure_supported!
            unless OpenSSL::PKey.respond_to?(:generate_key) && OpenSSL::PKey.respond_to?(:new_raw_public_key)
              raise UnsupportedError, "OpenSSL::PKey raw public key APIs are unavailable"
            end

            key = generate_x25519_key
            public_key = new_raw_public_key(key.raw_public_key)
            validate_key_bytes!(key.derive(public_key), "shared secret", KEY_BYTES)
          rescue OpenSSL::PKey::PKeyError => e
            raise UnsupportedError, e.message
          end

          def self.generate_x25519_key
            OpenSSL::PKey.generate_key(ALGORITHM)
          end

          def self.new_raw_public_key(key)
            validate_key_bytes!(key, "public key", KEY_BYTES)
            OpenSSL::PKey.new_raw_public_key(ALGORITHM, binary_string(key))
          end

          def self.validate_key_bytes!(key, label, expected_bytes)
            raise ArgumentError, "invalid X25519 #{label}" unless key.respond_to?(:bytesize) && key.bytesize == expected_bytes
          end

          def self.binary_string(string)
            string.dup.force_encoding('BINARY')
          end
          private_class_method :binary_string

          def digester
            OpenSSL::Digest::SHA256
          end

          private

          def generate_key
            self.class.generate_x25519_key
          end

          ## string   Q_C, client's ephemeral public key octet string
          def ecdh_public_key_bytes
            ecdh.raw_public_key
          end

          # compute shared secret from server's public key and client's private key
          def compute_shared_secret(server_ecdh_pubkey)
            pk = self.class.new_raw_public_key(server_ecdh_pubkey)
            OpenSSL::BN.new(ecdh.derive(pk), 2)
          end
        end
      end
    end
  end
end
