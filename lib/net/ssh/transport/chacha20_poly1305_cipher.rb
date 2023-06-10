require 'rbnacl'
require 'net/ssh/loggable'

module Net
  module SSH
    module Transport
      ## Implements the chacha20-poly1305@openssh cipher
      class ChaCha20Poly1305Cipher
        include Net::SSH::Loggable

        # Implicit HMAC, no need to do anything
        class ImplicitHMac
          def etm
            # TODO: ideally this shouln't be called
            true
          end

          def key_length
            64
          end
        end

        def initialize(encrypt:, key:)
          @chacha_hdr = OpenSSL::Cipher.new("chacha20")
          key_len = @chacha_hdr.key_len
          @chacha_main = OpenSSL::Cipher.new("chacha20")
          @poly = RbNaCl::OneTimeAuths::Poly1305
          if key.size < key_len * 2
            error { "chacha20_poly1305: keylength doesn't match" }
            raise "chacha20_poly1305: keylength doesn't match"
          end
          if encrypt
            @chacha_hdr.encrypt
            @chacha_main.encrypt
          else
            @chacha_hdr.decrypt
            @chacha_main.decrypt
          end
          main_key = key[0...key_len]
          @chacha_main.key = main_key
          hdr_key = key[key_len...(2 * key_len)]
          @chacha_hdr.key = hdr_key
        end

        def update_cipher_mac(payload, sequence_number)
          iv_data = [0, 0, 0, sequence_number].pack("NNNN")
          @chacha_main.iv = iv_data
          poly_key = @chacha_main.update(([0] * 32).pack('C32'))

          packet_length = payload.size
          length_data = [packet_length].pack("N")
          @chacha_hdr.iv = iv_data
          packet = @chacha_hdr.update(length_data)

          iv_data[0] = 1.chr
          @chacha_main.iv = iv_data
          unencrypted_data = payload
          packet += @chacha_main.update(unencrypted_data)

          packet += @poly.auth(poly_key, packet)
          return packet
        end

        def read_length(data, sequence_number)
          iv_data = [0, 0, 0, sequence_number].pack("NNNN")
          @chacha_hdr.iv = iv_data
          @chacha_hdr.update(data).unpack1("N")
        end

        def read_and_mac(data, mac, sequence_number)
          iv_data = [0, 0, 0, sequence_number].pack("NNNN")
          @chacha_main.iv = iv_data
          poly_key = @chacha_main.update(([0] * 32).pack('C32'))

          iv_data[0] = 1.chr
          @chacha_main.iv = iv_data
          unencrypted_data = @chacha_main.update(data[4..])
          begin
            ok = @poly.verify(poly_key, mac, data[0..])
            raise Net::SSH::Exception, "corrupted hmac detected #{name}" unless ok
          rescue RbNaCl::BadAuthenticatorError
            raise Net::SSH::Exception, "corrupted hmac detected #{name}"
          end
          return unencrypted_data
        end

        def mac_length
          16
        end

        def block_size
          8
        end

        def name
          "chacha20-poly1305@openssh.com"
        end

        def implicit_mac?
          true
        end

        def implicit_mac
          return ImplicitHMac.new
        end

        def self.block_size
          8
        end

        def self.key_length
          64
        end
      end
    end
  end
end
