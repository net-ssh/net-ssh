require 'rbnacl'

module Net
  module SSH
    module Transport
      class ChaCha20Poly1305Cipher
        def initialize(encrypt:, key:)
          @chacha_hdr = OpenSSL::Cipher.new("chacha20")
          key_len = @chacha_hdr.key_len
          @chacha_main = OpenSSL::Cipher.new("chacha20")
          @poly = RbNaCl::OneTimeAuths::Poly1305
          if key.size != key_len * 2
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
          @chacha_main.key = main_key # k2
          hdr_key = key[key_len...(2 * key_len)]
          @chacha_hdr.key = hdr_key # k1
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
          length_data = @chacha_hdr.update(data).unpack("N").first
        end

        def read_and_mac(data, mac, sequence_number)
          iv_data = [0, 0, 0, sequence_number].pack("NNNN")
          @chacha_main.iv = iv_data
          poly_key = @chacha_main.update(([0] * 32).pack('C32'))

          iv_data[0] = 1.chr
          @chacha_main.iv = iv_data
          unencrypted_data = @chacha_main.update(data[4..-1])
          begin
            ok = @poly.verify(poly_key, mac, data[0..-1])
            raise Net::SSH::Exception, "corrupted hmac detected #{name}" unless ok
          rescue RbNaCl::BadAuthenticatorError => e
            raise Net::SSH::Exception, "corrupted hmac detected #{name}"
          end
          return unencrypted_data
        end

        def mac_length
          16
        end

        def self.key_length
          64
        end

        def block_size
          8
        end

        def name
          "chacha20-poly1305@openssh.com"
        end

        class << self
          # A default block size of 8 is required by the SSH2 protocol.
          def block_size
            8
          end

          # Returns an arbitrary integer.
          def iv_len
            4
          end

          # Does nothing. Returns self.
          def encrypt
            self
          end

          # Does nothing. Returns self.
          def decrypt
            self
          end

          # Passes its single argument through unchanged.
          def update(text)
            text
          end

          # Returns the empty string.
          def final
            ""
          end

          # The name of this cipher, which is "chacha20-poly1305@openssh.com".
          def name
            "chacha20-poly1305@openssh.com"
          end

          # Does nothing. Returns nil.
          def iv=(v)
            nil
          end

          # Does nothing. Returns self.
          def reset
            self
          end
        end
      end
    end
  end
end
