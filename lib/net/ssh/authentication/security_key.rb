require 'net/ssh/authentication/pub_key_fingerprint'

module Net
  module SSH
    module Authentication
      # FIDO/U2F security keys held by ssh-agent. The agent does the signing (incl. user
      # presence); net-ssh only parses and re-serialises the public key blob (see PROTOCOL.u2f).
      module SecurityKey
        SK_ECDSA_SHA2_NISTP256 = "sk-ecdsa-sha2-nistp256@openssh.com"
        SK_SSH_ED25519 = "sk-ssh-ed25519@openssh.com"
        TYPES = [SK_ECDSA_SHA2_NISTP256, SK_SSH_ED25519].freeze

        def self.understands?(type)
          TYPES.include?(type)
        end

        # Public key of an agent-held security key; signing is delegated to the agent.
        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          attr_reader :ssh_type, :curve, :public_key_data, :application

          # Wire formats:
          #   sk-ecdsa-sha2-nistp256@openssh.com: string curve, string Q, string application
          #   sk-ssh-ed25519@openssh.com:         string public_key, string application
          def self.read_keyblob(type, buffer)
            case type
            when SK_ECDSA_SHA2_NISTP256
              curve = buffer.read_string
              public_key_data = buffer.read_string
              application = buffer.read_string
              new(type, public_key_data, application, curve: curve)
            when SK_SSH_ED25519
              public_key_data = buffer.read_string
              application = buffer.read_string
              new(type, public_key_data, application)
            else
              raise NotImplementedError, "unsupported security key type `#{type}'"
            end
          end

          def initialize(ssh_type, public_key_data, application, curve: nil)
            @ssh_type = ssh_type
            @public_key_data = public_key_data
            @application = application
            @curve = curve
          end

          def to_blob
            buffer = Net::SSH::Buffer.new
            buffer.write_string(ssh_type)
            buffer.write_string(curve) if curve
            buffer.write_string(public_key_data)
            buffer.write_string(application)
            buffer.to_s
          end

          def ssh_signature_type
            ssh_type
          end

          # Only used to de-duplicate identities, so a stable key-specific string suffices.
          def to_pem
            "#{ssh_type} #{[to_blob].pack('m0')}"
          end
        end
      end
    end
  end
end
