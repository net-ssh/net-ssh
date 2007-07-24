#--
# =============================================================================
# Copyright (c) 2004,2005 Jamis Buck (jamis@37signals.com)
# All rights reserved.
#
# This source file is distributed as part of the Net::SSH Secure Shell Client
# library for Ruby. This file (and the library as a whole) may be used only as
# allowed by either the BSD license, or the Ruby license (or, by association
# with the Ruby license, the GPL). See the "doc" subdirectory of the Net::SSH
# distribution for the texts of these licenses.
# -----------------------------------------------------------------------------
# net-ssh website : http://net-ssh.rubyforge.org
# project website: http://rubyforge.org/projects/net-ssh
# =============================================================================
#++

require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the host-based SSH authentication method.
        class Hostbased < Abstract
          include Constants

          def hostname
            session.transport.socket.client_name
          end

          # Attempts to perform host-based authorization of the user.
          def authenticate(next_service, username, password=nil)
            return false unless key_manager

            key_manager.identities.each do |identity|
              return true if authenticate_with(identity, next_service,
                username, key_manager)
            end

            return false
          end

          # Attempts to perform host-based authentication of the user, using
          # the given host identity (key).
          def authenticate_with(identity, next_service, username, key_manager)
            trace { "trying hostbased (#{identity.fingerprint})" }
            client_username = ENV['USER'] || username

            req = build_request(identity, next_service, username, "#{hostname}.", client_username)
            sig_data = Buffer.from(:string, session_id, :raw, req)

            sig = key_manager.sign(identity, sig_data.to_s)

            message = Buffer.from(:raw, req, :string, sig)

            send_message(message)
            message = session.next_message

            case message.type
              when USERAUTH_SUCCESS
                debug { "hostbased succeeded (#{identity.fingerprint})" }
                return true
              when USERAUTH_FAILURE
                trace { "hostbased failed (#{identity.fingerprint})" }
                return false
              else
                raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
            end
          end
          private :authenticate_with

          # Build the "core" hostbased request string.
          def build_request(identity, next_service, username, hostname, client_username)
            userauth_request(username, next_service, "hostbased", identity.ssh_type,
              Buffer.from(:key, identity).to_s, hostname, client_username).to_s
          end

        end

      end
    end
  end
end
