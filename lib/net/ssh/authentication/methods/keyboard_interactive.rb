require 'net/ssh/authentication/methods/abstract'

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the "keyboard-interactive" SSH authentication method.
        class KeyboardInteractive < Abstract
          # Represents an information request from the server
          InfoRequest = Struct.new(:name, :instruction, :password, :prompts)

          # Represents a single prompt in an InfoRequest.
          Prompt = Struct.new(:prompt, :echo)

          USERAUTH_INFO_REQUEST  = 60
          USERAUTH_INFO_RESPONSE = 61

          # Attempt to authenticate the given user for the given service.
          def authenticate(next_service, username, password=nil)
            trace { "trying keyboard-interactive" }
            send_message(userauth_request(username, next_service, "keyboard-interactive", "", ""))

            loop do
              message = session.next_message

              case message.type
              when USERAUTH_SUCCESS
                debug { "keyboard-interactive succeeded" }
                return true
              when USERAUTH_FAILURE
                trace { "keyboard-interactive failed" }
                return false
              when USERAUTH_INFO_REQUEST
                name = message.read_string
                instruction = message.read_string
                trace { "keyboard-interactive info request" }

                req = InfoRequest.new(name, instruction, password, [])
                password = nil # only use the given password once

                lang_tag = message.read_string
                message.read_long.times do
                  prompt = message.read_string
                  echo = message.read_bool
                  req.prompts << Prompt.new(prompt, echo)
                end

                responses = prompt(req)
                msg = Buffer.from(:byte, USERAUTH_INFO_RESPONSE, :long, responses.length, :string, responses)
                send_message(msg)
              else
                raise Net::SSH::Exception, "unexpected reply in keyboard interactive: #{message.type} (#{message.inspect})"
              end
            end
          end

          def prompt(req)
            if @options[:keyboard_interactive].respond_to?(:call)
              @options[:keyboard_interactive].call(req)
            else
              [@options[:keyboard_interactive] || ""] * req.prompts.length
            end
          end
        end

      end
    end
  end
end
