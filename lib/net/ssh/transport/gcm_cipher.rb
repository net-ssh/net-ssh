require 'net/ssh/loggable'

module Net
  module SSH
    module Transport
      ## Extension module for aes(128|256)gcm ciphers
      module GCMCipher
        # rubocop:disable Metrics/AbcSize
        def self.extended(orig)
          # rubocop:disable Metrics/BlockLength
          orig.class_eval do
            include Net::SSH::Loggable

            attr_reader   :cipher
            attr_reader   :key
            attr_accessor :nonce

            #
            # Semantically gcm cipher supplies the OpenSSL iv interface with a nonce
            #   as it is not randomly generated due to being supplied from a counter.
            # The RFC's use IV and nonce interchangeably.
            #
            def initialize(encrypt:, key:)
              @cipher = OpenSSL::Cipher.new(algo_name)
              @key    = key
              key_len = @cipher.key_len
              if key.size != key_len
                error_message = "#{cipher_name}: keylength does not match"
                error { error_message }
                raise error_message
              end
              encrypt ? @cipher.encrypt : @cipher.decrypt
              @cipher.key = key

              @nonce = {
                fixed: nil,
                invocation_counter: 0
              }
            end

            def update_cipher_mac(payload, _sequence_number)
              #
              # --- RFC 5647 7.3 ---
              # When using AES-GCM with secure shell, the packet_length field is to
              # be treated as additional authenticated data, not as plaintext.
              #
              length_data      = [payload.bytesize].pack('N')

              cipher.auth_data = length_data

              encrypted_data   = cipher.update(payload) << cipher.final

              mac              = cipher.auth_tag

              incr_nonce
              length_data + encrypted_data + mac
            end

            #
            # --- RFC 5647 ---
            # uint32    packet_length;  // 0 <= packet_length < 2^32
            #
            def read_length(data, _sequence_number)
              data.unpack1('N')
            end

            #
            # --- RFC 5647 ---
            # In AES-GCM secure shell, the inputs to the authenticated encryption
            # are:
            #  PT (Plain Text)
            #      byte      padding_length; // 4 <= padding_length < 256
            #      byte[n1]  payload;        // n1 = packet_length-padding_length-1
            #      byte[n2]  random_padding; // n2 = padding_length
            #  AAD (Additional Authenticated Data)
            #      uint32    packet_length;  // 0 <= packet_length < 2^32
            #  IV (Initialization Vector)
            #      As described in section 7.1.
            #  BK (Block Cipher Key)
            #      The appropriate Encryption Key formed during the Key Exchange.
            #
            def read_and_mac(data, mac, _sequence_number)
              # The authentication tag will be placed in the MAC field at the end of the packet

              # OpenSSL does not verify auth tag length
              # GCM mode allows arbitrary sizes for the auth_tag up to 128 bytes and a single
              #   byte allows authentication to pass. If single byte auth tags are possible
              #   an attacker would require no more than 256 attempts to forge a valid tag.
              #
              raise 'incorrect auth_tag length' unless mac.to_s.length == mac_length

              packet_length    = data.unpack1('N')

              cipher.auth_tag  = mac.to_s
              cipher.auth_data = [packet_length].pack('N')

              result = cipher.update(data[4...]) << cipher.final
              incr_nonce
              result
            end

            def mac_length
              16
            end

            def block_size
              16
            end

            def self.block_size
              16
            end

            #
            # --- RFC 5647 ---
            # N_MIN       minimum nonce (IV) length        12 octets
            # N_MAX       maximum nonce (IV) length        12 octets
            #
            def iv_len
              12
            end

            #
            # --- RFC 5288 ---
            # Each value of the nonce_explicit MUST be distinct for each distinct
            # invocation of the GCM encrypt function for any fixed key. Failure to
            # meet this uniqueness requirement can significantly degrade security.
            # The nonce_explicit MAY be the 64-bit sequence number.
            #
            # --- RFC 5116 ---
            # (2.1) Applications that can generate distinct nonces SHOULD use the nonce
            # formation method defined in Section 3.2, and MAY use any
            # other method that meets the uniqueness requirement.
            #
            # (3.2) The following method to construct nonces is RECOMMENDED.
            #
            #  <- variable -> <- variable ->
            #  - - - - - - -  - - - - - - -
            # |    fixed     |    counter   |
            #
            # Initial octets consist of a fixed field and final octets consist of a
            # Counter field. Implementations SHOULD support 12-octet nonces in which
            # the Counter field is four octets long.
            # The Counter fields of successive nonces form a monotonically increasing
            # sequence, when those fields are regarded as unsignd integers in network
            # byte order.
            # The Counter part SHOULD be equal to zero for the first nonce and increment
            # by one for each successive nonce that is generated.
            # The Fixed field MUST remain constant for all nonces that are generated for
            # a given encryption device.
            #
            # --- RFC 5647 ---
            # The invocation field is treated as a 64-bit integer and is increment after
            # each invocation of AES-GCM to process a binary packet.
            # AES-GCM produces a keystream in blocks of 16-octets that is used to
            # encrypt the plaintext. This keystream is produced by encrypting the
            # following 16-octet data structure:
            #
            # uint32 fixed;              // 4 octets
            # uint64 invocation_counter; // 8 octets
            # unit32 block_counter;      // 4 octets
            #
            # The block_counter is initially set to one (1) and increment as each block
            # of key is produced.
            #
            # The reader is reminded that SSH requires that the data to be encrypted
            # MUST be padded out to a multiple of the block size (16-octets for AES-GCM).
            #
            def incr_nonce
              return if nonce[:fixed].nil?

              nonce[:invocation_counter] = [nonce[:invocation_counter].to_s.unpack1('B*').to_i(2) + 1].pack('Q>*')

              apply_nonce
            end

            def nonce=(iv_s)
              return if nonce[:fixed]

              nonce[:fixed]              = iv_s[0...4]
              nonce[:invocation_counter] = iv_s[4...12]

              apply_nonce
            end

            def apply_nonce
              cipher.iv = "#{nonce[:fixed]}#{nonce[:invocation_counter]}"
            end

            #
            # --- RFC 5647 ---
            # If AES-GCM is selected as the encryption algorithm for a given
            # tunnel, AES-GCM MUST also be selected as the Message Authentication
            # Code (MAC) algorithm.  Conversely, if AES-GCM is selected as the MAC
            # algorithm, it MUST also be selected as the encryption algorithm.
            #
            def implicit_mac?
              true
            end
          end
        end
        # rubocop:enable Metrics/BlockLength
      end
      # rubocop:enable Metrics/AbcSize
    end
  end
end
