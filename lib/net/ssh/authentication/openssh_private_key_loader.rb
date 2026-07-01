require 'net/ssh/transport/cipher_factory'

module Net
  module SSH
    module Authentication
      # Loads private keys encoded in the OpenSSH private key container format.
      #
      # This loader is shared by RSA, ECDSA, and ED25519 keys. It originally
      # lived under the ED25519 namespace, but the OpenSSH private key format is
      # not ED25519-specific. Keeping this loader outside that namespace allows
      # OpenSSH-format RSA/ECDSA keys to be loaded without ED25519 dependencies.
      class OpenSSHPrivateKeyLoader
        CipherFactory = Net::SSH::Transport::CipherFactory

        MBEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        MEND = "-----END OPENSSH PRIVATE KEY-----"
        MAGIC = "openssh-key-v1"

        # Raised when an OpenSSH private key cannot be decrypted.
        class DecryptError < ArgumentError
          def initialize(message, encrypted_key: false)
            super(message)
            @encrypted_key = encrypted_key
          end

          def encrypted_key?
            @encrypted_key
          end
        end

        def self.read(datafull, password)
          datafull = datafull.strip
          raise ArgumentError, "Expected #{MBEGIN} at start of private key" unless datafull.start_with?(MBEGIN)
          raise ArgumentError, "Expected #{MEND} at end of private key" unless datafull.end_with?(MEND)

          datab64 = datafull[MBEGIN.size...-MEND.size]
          data = datab64.unpack1("m")
          raise ArgumentError, "Expected #{MAGIC} at start of decoded private key" unless data.start_with?(MAGIC)

          buffer = Net::SSH::Buffer.new(data[MAGIC.size + 1..-1])

          ciphername = buffer.read_string
          raise ArgumentError, "#{ciphername} in private key is not supported" unless CipherFactory.supported?(ciphername)

          kdfname = buffer.read_string
          raise ArgumentError, "Expected #{kdfname} to be or none or bcrypt" unless %w[none bcrypt].include?(kdfname)

          kdfopts = Net::SSH::Buffer.new(buffer.read_string)
          num_keys = buffer.read_long
          raise ArgumentError, "Only 1 key is supported in ssh keys #{num_keys} was in private key" unless num_keys == 1

          _pubkey = buffer.read_string

          len = buffer.read_long

          keylen, blocksize, ivlen = CipherFactory.get_lengths(ciphername, iv_len: true)
          raise ArgumentError, "Private key len:#{len} is not a multiple of #{blocksize}" if
            (len < blocksize) || ((blocksize > 0) && (len % blocksize) != 0)

          if kdfname == 'bcrypt'
            raise "BCryptPbkdf is not implemented for jruby" if RUBY_PLATFORM == "java"

            require 'bcrypt_pbkdf'

            salt = kdfopts.read_string
            rounds = kdfopts.read_long

            key = BCryptPbkdf::key(password, salt, keylen + ivlen, rounds)
            raise DecryptError.new("BCyryptPbkdf failed", encrypted_key: true) unless key
          else
            key = '\x00' * (keylen + ivlen)
          end

          cipher = CipherFactory.get(ciphername, key: key[0...keylen], iv: key[keylen...keylen + ivlen], decrypt: true)

          decoded = cipher.update(buffer.remainder_as_buffer.to_s)
          decoded << cipher.final

          decoded = Net::SSH::Buffer.new(decoded)
          check1 = decoded.read_long
          check2 = decoded.read_long

          raise DecryptError.new("Decrypt failed on private key", encrypted_key: kdfname == 'bcrypt') if check1 != check2

          type_name = decoded.read_string
          case type_name
          when "ssh-ed25519"
            Net::SSH::Authentication::ED25519Loader.raiseUnlessLoaded("ed25519 keys only supported if ED25519 is available")
            Net::SSH::Authentication::ED25519::PrivKey.new(decoded)
          else
            decoded.read_private_keyblob(type_name)
          end
        end
      end
    end
  end
end
