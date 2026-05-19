gem 'ed25519', '~> 1.2'
gem 'bcrypt_pbkdf', '~> 1.0' unless RUBY_PLATFORM == "java"

require 'ed25519'

require 'net/ssh/transport/cipher_factory'
require 'net/ssh/authentication/pub_key_fingerprint'
require 'net/ssh/authentication/openssh_private_key_loader'
require 'bcrypt_pbkdf' unless RUBY_PLATFORM == "java"

module Net
  module SSH
    module Authentication
      module ED25519
        class SigningKeyFromFile < SimpleDelegator
          def initialize(pk, sk)
            key = ::Ed25519::SigningKey.from_keypair(sk)
            raise ArgumentError, "pk does not match sk" unless pk == key.verify_key.to_bytes

            super(key)
          end
        end

        # Keep the old ED25519::OpenSSHPrivateKeyLoader constant for backward
        # compatibility. The implementation now lives outside the ED25519
        # namespace because OpenSSH private keys can contain RSA/ECDSA keys too.
        OpenSSHPrivateKeyLoader = Net::SSH::Authentication::OpenSSHPrivateKeyLoader

        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          attr_reader :verify_key

          def initialize(data)
            @verify_key = ::Ed25519::VerifyKey.new(data)
          end

          def self.read_keyblob(buffer)
            PubKey.new(buffer.read_string)
          end

          def to_blob
            Net::SSH::Buffer.from(:mstring, "ssh-ed25519".dup, :string, @verify_key.to_bytes).to_s
          end

          def ssh_type
            "ssh-ed25519"
          end

          def ssh_signature_type
            ssh_type
          end

          def ssh_do_verify(sig, data, options = {})
            @verify_key.verify(sig, data)
          end

          def to_pem
            # TODO this is not pem
            ssh_type + [@verify_key.to_bytes].pack("m")
          end
        end

        class PrivKey
          CipherFactory = Net::SSH::Transport::CipherFactory

          MBEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
          MEND = "-----END OPENSSH PRIVATE KEY-----\n"
          MAGIC = "openssh-key-v1"

          attr_reader :sign_key

          def initialize(buffer)
            pk = buffer.read_string
            sk = buffer.read_string
            _comment = buffer.read_string

            @pk = pk
            @sign_key = SigningKeyFromFile.new(pk, sk)
          end

          def to_blob
            public_key.to_blob
          end

          def ssh_type
            "ssh-ed25519"
          end

          def ssh_signature_type
            ssh_type
          end

          def public_key
            PubKey.new(@pk)
          end

          def ssh_do_sign(data, sig_alg = nil)
            @sign_key.sign(data)
          end

          def self.read(data, password)
            OpenSSHPrivateKeyLoader.read(data, password)
          end
        end
      end
    end
  end
end
