require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods
        # Implements the "publickey" SSH authentication method.
        class Publickey < Abstract
          RSA_CERT = "ssh-rsa-cert-v01@openssh.com".freeze

          # Key algorithms usable with each RSA key type, mapped to the signature algorithm they imply.
          RSA_SIGNATURE_ALGORITHMS = {
            "ssh-rsa" => {
              "rsa-sha2-512" => "rsa-sha2-512",
              "rsa-sha2-256" => "rsa-sha2-256",
              "ssh-rsa" => "ssh-rsa"
            }.freeze,
            RSA_CERT => {
              "rsa-sha2-512-cert-v01@openssh.com" => "rsa-sha2-512",
              "rsa-sha2-256-cert-v01@openssh.com" => "rsa-sha2-256",
              RSA_CERT => "ssh-rsa"
            }.freeze
          }.freeze

          # Servers that OpenSSH flags with SSH_BUG_SIGTYPE (compat.c): no RSA/SHA-2 certificate signatures.
          SIGTYPE_BUG = /\A(OpenSSH_[2-5]|OpenSSH_6\.[56]|OpenSSH_7\.[0-7]|Sun_SSH_1\.0)/.freeze

          # Attempts to perform public-key authentication for the given
          # username, trying each identity known to the key manager. If any of
          # them succeed, returns +true+, otherwise returns +false+. This
          # requires the presence of a key manager.
          def authenticate(next_service, username, password = nil)
            return false unless key_manager

            debug { "pubkey_algorithms: #{pubkey_algorithms.join(', ')}" }

            key_manager.each_identity do |identity|
              return true if authenticate_with(identity, next_service, username)
            end

            return false
          end

          private

          # Builds a packet that contains the request formatted for sending
          # a public-key request to the server.
          def build_request(pub_key, username, next_service, alg, has_sig)
            blob = Net::SSH::Buffer.new
            blob.write_key pub_key

            userauth_request(username, next_service, "publickey", has_sig,
                             alg, blob.to_s)
          end

          # Builds and sends a request formatted for a public-key
          # authentication request.
          def send_request(pub_key, username, next_service, alg, signature = nil)
            msg = build_request(pub_key, username, next_service, alg,
                                !signature.nil?)
            msg.write_string(signature) if signature
            send_message(msg)
          end

          def authenticate_with_alg(identity, next_service, username, alg, sig_alg = nil)
            debug { "trying publickey (#{fingerprint(identity)}) alg #{alg}" }
            send_request(identity, username, next_service, alg)

            message = session.next_message

            case message.type
            when USERAUTH_PK_OK
              buffer = build_request(identity, username, next_service, alg,
                                     true)
              sig_data = Net::SSH::Buffer.new
              sig_data.write_string(session_id)
              sig_data.append(buffer.to_s)

              sig_blob = key_manager.sign(identity, sig_data, sig_alg)

              send_request(identity, username, next_service, alg, sig_blob.to_s)
              message = session.next_message

              case message.type
              when USERAUTH_SUCCESS
                debug { "publickey succeeded (#{fingerprint(identity)})" }
                return true
              when USERAUTH_FAILURE
                debug { "publickey failed (#{fingerprint(identity)})" }

                raise Net::SSH::Authentication::DisallowedMethod unless
                  message[:authentications].split(/,/).include? 'publickey'

                return false
              else
                raise Net::SSH::Exception,
                      "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
              end

            when USERAUTH_FAILURE
              return false
            when USERAUTH_SUCCESS
              return true

            else
              raise Net::SSH::Exception, "unexpected reply to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
            end
          end

          # Attempts to perform public-key authentication for the given
          # username, with the given identity (public key). Returns +true+ if
          # successful, or +false+ otherwise.
          def authenticate_with(identity, next_service, username)
            alg = key_algorithm(identity)
            if alg.nil?
              debug { "skipping publickey (#{identity.fingerprint}): no mutual signature algorithm for #{identity.ssh_type}" }
              return false
            end

            authenticate_with_alg(identity, next_service, username, alg, RSA_SIGNATURE_ALGORITHMS.dig(identity.ssh_type, alg))
          end

          # Picks the single algorithm to offer for the identity, following
          # key_sig_algorithm() in OpenSSH 10.2 sshconnect2.c.
          def key_algorithm(identity)
            type = identity.ssh_type
            server_sig_algs = session.transport.server_sig_algs
            server_software = session.transport.server_version.version.to_s.sub(/\ASSH-[\d.]+-/, "")

            if server_sig_algs.nil? || !RSA_SIGNATURE_ALGORITHMS.key?(type) ||
               (type == RSA_CERT && server_software.match?(SIGTYPE_BUG))
              return type if pubkey_algorithms.include?(type)

              return nil
            end

            # OpenSSH 7.4 accepts RSA/SHA-2 signatures but leaves them out of server-sig-algs.
            server_sig_algs = %w[rsa-sha2-256 rsa-sha2-512] if type == "ssh-rsa" && server_software.start_with?("OpenSSH_7.4")

            pubkey_algorithms.find do |alg|
              sig_alg = RSA_SIGNATURE_ALGORITHMS[type][alg]
              sig_alg && server_sig_algs.include?(sig_alg)
            end
          end
        end
      end
    end
  end
end
