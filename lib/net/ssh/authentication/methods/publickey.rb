require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods
        # Implements the "publickey" SSH authentication method.
        class Publickey < Abstract
          # Attempts to perform public-key authentication for the given
          # username, trying each identity known to the key manager. If any of
          # them succeed, returns +true+, otherwise returns +false+. This
          # requires the presence of a key manager.
          def authenticate(next_service, username, password = nil)
            return false unless key_manager

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
            debug { "trying publickey (#{identity.fingerprint})" }
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
                debug { "publickey succeeded (#{identity.fingerprint})" }
                return true
              when USERAUTH_FAILURE
                debug { "publickey failed (#{identity.fingerprint})" }

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
            type = identity.ssh_type
            if type == "ssh-rsa"
              pubkey_algorithms.each do |pk_alg|
                case pk_alg
                when "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"
                  if authenticate_with_alg(identity, next_service, username, pk_alg, pk_alg)
                    # success
                    return true
                  end
                end
              end
            elsif type == "ssh-rsa-cert-v01@openssh.com"
              pubkey_algorithms.each do |pk_alg|
                case pk_alg
                when "rsa-sha2-512-cert-v01@openssh.com"
                  if authenticate_with_alg(identity, next_service, username, pk_alg, "rsa-sha2-512")
                    # success
                    return true
                  end
                when "rsa-sha2-256-cert-v01@openssh.com"
                  if authenticate_with_alg(identity, next_service, username, pk_alg, "rsa-sha2-256")
                    # success
                    return true
                  end
                when "ssh-rsa-cert-v01@openssh.com"
                  if authenticate_with_alg(identity, next_service, username, pk_alg)
                    # success
                    return true
                  end
                end
              end
            elsif authenticate_with_alg(identity, next_service, username, type)
              # success
              return true
            end
            # failure
            return false
          end
        end
      end
    end
  end
end
