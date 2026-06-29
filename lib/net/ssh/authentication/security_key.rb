require 'net/ssh/authentication/pub_key_fingerprint'

module Net
  module SSH
    module Authentication
      # Support for FIDO/U2F hardware "security key" public keys, i.e. the
      # +sk-ecdsa-sha2-nistp256@openssh.com+ and +sk-ssh-ed25519@openssh.com+
      # key types created by <tt>ssh-keygen -t ecdsa-sk</tt> / <tt>-t ed25519-sk</tt>.
      #
      # == Agent only
      #
      # This implements *agent-backed* security keys only. Net::SSH does not talk
      # to the hardware authenticator directly (that requires a FIDO/CTAP stack
      # such as libfido2), so:
      #
      # * security keys *must* be provided by a running ssh-agent
      #   (the agent performs the actual signing, including the required user
      #   presence / touch), and
      # * loading +sk-*+ keys from private key files on disk is *not* supported.
      #
      # Because the agent does the signing, Net::SSH only needs to understand the
      # public key well enough to (a) parse the blob the agent advertises and
      # (b) re-serialize that exact blob when building authentication and signing
      # requests. The agent returns a ready-made SSH signature blob that Net::SSH
      # forwards to the server verbatim.
      #
      # See OpenSSH's PROTOCOL.u2f for the wire formats.
      module SecurityKey
        # OpenSSH public key algorithm name for ECDSA (NIST P-256) security keys.
        SK_ECDSA_SHA2_NISTP256 = "sk-ecdsa-sha2-nistp256@openssh.com"

        # OpenSSH public key algorithm name for Ed25519 security keys.
        SK_SSH_ED25519 = "sk-ssh-ed25519@openssh.com"

        # The +sk-*+ public key algorithm names supported here.
        TYPES = [SK_ECDSA_SHA2_NISTP256, SK_SSH_ED25519].freeze

        # Returns true if +type+ is a (non-certificate) security key public key
        # algorithm name handled by this module.
        def self.understands?(type)
          TYPES.include?(type)
        end

        # A public key for a FIDO/U2F security key. It can report its type and
        # fingerprint and round-trip its wire blob; all signing is delegated to
        # the ssh-agent that holds the corresponding credential.
        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          attr_reader :ssh_type, :curve, :public_key_data, :application

          # Reads the public key fields for +type+ from +buffer+ (the leading
          # type string has already been consumed by Buffer#read_key). Wire
          # formats per PROTOCOL.u2f:
          #
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

          # The signature algorithm used with this key. Security keys do not have
          # alternate signature types, so this is just the key type.
          def ssh_signature_type
            ssh_type
          end

          # Security keys have no OpenSSL PEM representation. The key manager only
          # uses #to_pem to de-duplicate identities, so a stable, key-specific
          # string is sufficient (and will simply never match a real PEM).
          def to_pem
            "#{ssh_type} #{[to_blob].pack('m0')}"
          end
        end
      end
    end
  end
end
