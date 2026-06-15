require 'openssl'
require 'net/ssh/loggable'

module Net
  module SSH
    module Transport
      ## Implements the chacha20-poly1305@openssh cipher
      class ChaCha20Poly1305Cipher
        include Net::SSH::Loggable

        POLY1305_ALGORITHM = "POLY1305"
        POLY1305_KEY_BYTES = 32
        POLY1305_TAG_BYTES = 16
        ZERO_BLOCK = "\x00".b * POLY1305_KEY_BYTES
        ZERO_IV = "\x00".b * 16

        class UnsupportedError < StandardError; end

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
          iv_data = packet_iv(sequence_number)
          @chacha_main.iv = iv_data
          poly_key = @chacha_main.update(ZERO_BLOCK)

          packet_length = payload.size
          length_data = [packet_length].pack("N")
          @chacha_hdr.iv = iv_data
          packet = @chacha_hdr.update(length_data)

          iv_data[0] = 1.chr
          @chacha_main.iv = iv_data
          unencrypted_data = payload
          packet += @chacha_main.update(unencrypted_data)

          packet += self.class.poly1305_auth(poly_key, packet)
          return packet
        end

        def read_length(data, sequence_number)
          iv_data = packet_iv(sequence_number)
          @chacha_hdr.iv = iv_data
          @chacha_hdr.update(data).unpack1("N")
        end

        def read_and_mac(data, mac, sequence_number)
          iv_data = packet_iv(sequence_number)
          @chacha_main.iv = iv_data
          poly_key = @chacha_main.update(ZERO_BLOCK)

          iv_data[0] = 1.chr
          @chacha_main.iv = iv_data
          unencrypted_data = @chacha_main.update(data[4..])

          expected_mac = self.class.poly1305_auth(poly_key, data[0..])
          valid_mac = mac.respond_to?(:bytesize) &&
                      mac.bytesize == POLY1305_TAG_BYTES &&
                      OpenSSL.fixed_length_secure_compare(expected_mac, mac)
          raise Net::SSH::Exception, "corrupted hmac detected #{name}" unless valid_mac

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

        def self.ensure_supported!
          raise UnsupportedError, "OpenSSL::PKey raw private key APIs are unavailable" unless OpenSSL::PKey.respond_to?(:new_raw_private_key)

          OpenSSL::Cipher.new("chacha20")

          tag = poly1305_auth("\x00" * POLY1305_KEY_BYTES, "")
          raise UnsupportedError, "OpenSSL Poly1305 authentication failed" unless tag.bytesize == POLY1305_TAG_BYTES
        rescue OpenSSL::Cipher::CipherError, OpenSSL::PKey::PKeyError => e
          raise UnsupportedError, e.message
        end

        def self.poly1305_auth(poly_key, data)
          validate_poly1305_key!(poly_key)
          OpenSSL::PKey.new_raw_private_key(POLY1305_ALGORITHM, binary_string(poly_key)).sign(nil, binary_string(data))
        end

        def self.validate_poly1305_key!(poly_key)
          raise ArgumentError, "invalid Poly1305 key" unless poly_key.respond_to?(:bytesize) && poly_key.bytesize == POLY1305_KEY_BYTES
        end

        def self.binary_string(string)
          string.dup.force_encoding('BINARY')
        end
        private_class_method :binary_string

        def packet_iv(sequence_number)
          iv_data = ZERO_IV.dup
          iv_data.setbyte(12, (sequence_number >> 24) & 0xff)
          iv_data.setbyte(13, (sequence_number >> 16) & 0xff)
          iv_data.setbyte(14, (sequence_number >> 8) & 0xff)
          iv_data.setbyte(15, sequence_number & 0xff)
          iv_data
        end
        private :packet_iv
      end
    end
  end
end
