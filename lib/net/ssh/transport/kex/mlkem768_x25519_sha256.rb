require 'openssl'
require 'net/ssh/buffer'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex/abstract'

module Net
  module SSH
    module Transport
      module Kex
        # Hybrid ML-KEM-768 and X25519 key exchange used by OpenSSH.
        class MLKEM768X25519Sha256 < Abstract
          MLKEM_ALGORITHM = "ML-KEM-768"
          MLKEM_PUBLIC_KEY_BYTES = 1184
          MLKEM_PRIVATE_KEY_BYTES = 2400
          MLKEM_CIPHERTEXT_BYTES = 1088
          MLKEM_SHARED_SECRET_BYTES = 32
          X25519_ALGORITHM = "X25519"
          X25519_KEY_BYTES = 32

          class UnsupportedError < StandardError; end

          # Wrapper for OpenSSH's string-encoded hybrid shared secret.
          class StringEncodedSharedSecret
            def initialize(bytes)
              @bytes = bytes
            end

            def to_ssh
              @bytes
            end

            def ==(other)
              other.respond_to?(:to_ssh) && to_ssh == other.to_ssh
            end
          end

          def self.ensure_supported!
            raise UnsupportedError, "openssl gem >= 4.0.0 is required" unless Gem::Version.new(OpenSSL::VERSION) >= Gem::Version.new("4.0.0")

            unless OpenSSL::PKey::PKey.method_defined?(:encapsulate) &&
                   OpenSSL::PKey::PKey.method_defined?(:decapsulate)
              raise UnsupportedError, "OpenSSL::PKey KEM APIs are unavailable"
            end

            mlkem_key = generate_mlkem_key
            validate_mlkem_key_bytes!(mlkem_key.raw_public_key, "public key", MLKEM_PUBLIC_KEY_BYTES)
            validate_mlkem_key_bytes!(mlkem_key.raw_private_key, "private key", MLKEM_PRIVATE_KEY_BYTES)

            mlkem_public_key = new_mlkem_public_key(mlkem_key.raw_public_key)
            ciphertext, client_secret = mlkem_public_key.encapsulate
            server_secret = mlkem_key.decapsulate(ciphertext)

            validate_mlkem_key_bytes!(ciphertext, "ciphertext", MLKEM_CIPHERTEXT_BYTES)
            validate_mlkem_key_bytes!(client_secret, "shared secret", MLKEM_SHARED_SECRET_BYTES)
            raise UnsupportedError, "OpenSSL ML-KEM-768 shared secret decapsulation failed" if client_secret != server_secret
          rescue OpenSSL::PKey::PKeyError, ArgumentError => e
            raise UnsupportedError, e.message
          end

          def self.generate_mlkem_key
            OpenSSL::PKey.generate_key(MLKEM_ALGORITHM)
          end

          def self.generate_x25519_key
            OpenSSL::PKey.generate_key(X25519_ALGORITHM)
          end

          def self.new_mlkem_public_key(key)
            validate_mlkem_key_bytes!(key, "public key", MLKEM_PUBLIC_KEY_BYTES)
            OpenSSL::PKey.new_raw_public_key(MLKEM_ALGORITHM, binary_string(key))
          end

          def self.new_x25519_public_key(key)
            validate_x25519_key_bytes!(key, "public key")
            OpenSSL::PKey.new_raw_public_key(X25519_ALGORITHM, binary_string(key))
          end

          def self.validate_mlkem_key_bytes!(key, label, expected_bytes)
            raise ArgumentError, "invalid ML-KEM-768 #{label}" unless key.respond_to?(:bytesize) && key.bytesize == expected_bytes
          end

          def self.validate_x25519_key_bytes!(key, label)
            raise ArgumentError, "invalid X25519 #{label}" unless key.respond_to?(:bytesize) && key.bytesize == X25519_KEY_BYTES
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
            {
              mlkem: self.class.generate_mlkem_key,
              x25519: self.class.generate_x25519_key
            }
          end

          def client_public_key_bytes
            @client_public_key_bytes ||= dh.fetch(:mlkem).raw_public_key + dh.fetch(:x25519).raw_public_key
          end

          def build_signature_buffer(result)
            response = Net::SSH::Buffer.new
            response.write_string data[:client_version_string],
                                  data[:server_version_string],
                                  data[:client_algorithm_packet],
                                  data[:server_algorithm_packet],
                                  result[:key_blob],
                                  client_public_key_bytes,
                                  result[:server_blob]
            response.write result[:shared_secret].to_ssh
            response
          end

          def send_kexinit
            buffer = Net::SSH::Buffer.from(:byte, KEXECDH_INIT, :mstring, client_public_key_bytes)
            connection.send_message(buffer)

            buffer = connection.next_message
            raise Net::SSH::Exception, 'expected REPLY' unless buffer.type == KEXECDH_REPLY

            result = {}
            result[:key_blob] = buffer.read_string
            result[:server_key] = Net::SSH::Buffer.new(result[:key_blob]).read_key
            result[:server_blob] = buffer.read_string
            result[:shared_secret] = compute_shared_secret(result[:server_blob])

            sig_buffer = Net::SSH::Buffer.new(buffer.read_string)
            sig_type = sig_buffer.read_string
            if sig_type != algorithms.host_key_format
              raise Net::SSH::Exception, "host key algorithm mismatch for signature '#{sig_type}' != '#{algorithms.host_key_format}'"
            end

            result[:server_sig] = sig_buffer.read_string

            result
          end

          def compute_shared_secret(server_blob)
            unless server_blob.respond_to?(:bytesize) && server_blob.bytesize == MLKEM_CIPHERTEXT_BYTES + X25519_KEY_BYTES
              raise Net::SSH::Exception, "invalid mlkem768x25519-sha256 server key"
            end

            ciphertext = server_blob.byteslice(0, MLKEM_CIPHERTEXT_BYTES)
            server_x25519 = server_blob.byteslice(MLKEM_CIPHERTEXT_BYTES, X25519_KEY_BYTES)

            mlkem_secret = dh.fetch(:mlkem).decapsulate(ciphertext)
            self.class.validate_mlkem_key_bytes!(mlkem_secret, "shared secret", MLKEM_SHARED_SECRET_BYTES)

            server_x25519_key = self.class.new_x25519_public_key(server_x25519)
            x25519_secret = dh.fetch(:x25519).derive(server_x25519_key)
            self.class.validate_x25519_key_bytes!(x25519_secret, "shared secret")

            hash = digester.digest(mlkem_secret + x25519_secret)
            StringEncodedSharedSecret.new(Net::SSH::Buffer.from(:string, hash).to_s)
          end
        end
      end
    end
  end
end
