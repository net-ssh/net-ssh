require 'net/ssh/loggable'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/authentication/key_manager'
require 'net/ssh/authentication/methods/publickey'
require 'net/ssh/authentication/methods/hostbased'
require 'net/ssh/authentication/methods/password'
require 'net/ssh/authentication/methods/keyboard_interactive'

module Net; module SSH; module Authentication
  class Session
    include Transport::Constants, Constants, Loggable

    # transport session
    attr_reader :transport

    attr_reader :auth_methods
    attr_reader :allowed_auth_methods
    attr_reader :options

    def initialize(transport, options={})
      self.logger = transport.logger
      @transport = transport

      @auth_methods = options[:auth_methods] || %w(publickey hostbased password keyboard-interactive)
      @options = options

      @allowed_auth_methods = @auth_methods
    end

    def authenticate(next_service, username, password=nil)
      trace { "beginning authentication of `#{username}'" }

      transport.send_message(transport.service_request("ssh-userauth"))
      message = expect_message(SERVICE_ACCEPT)

      key_manager = KeyManager.new(logger)
      Array(options[:keys]).each { |key| key_manager.add(key) }

      attempted = []

      @auth_methods.each do |name|
        next unless @allowed_auth_methods.include?(name)
        attempted << name

        debug { "trying #{name}" }
        method = Methods.const_get(name.split(/\W+/).map { |p| p.capitalize }.join).new(self, :key_manager => key_manager)

        return true if method.authenticate(next_service, username, password)
      end

      error { "all authorization methods failed (tried #{attempted.join(', ')})" }
      return false
    ensure
      key_manager.finish if key_manager
    end

    def next_message
      loop do
        packet = transport.next_message

        case packet.type
        when USERAUTH_BANNER
          log { packet[:message] }
          # TODO add a hook for people to retrieve the banner when it is sent

        when USERAUTH_FAILURE
          @allowed_auth_methods = packet[:authentications].split(/,/)
          trace { "allowed methods: #{packet[:authentications]}" }
          return packet

        when USERAUTH_METHOD_RANGE, SERVICE_ACCEPT
          return packet

        when USERAUTH_SUCCESS
          transport.hint :authenticated
          return packet

        else
          raise Net::SSH::Exception, "unexpected message #{packet.type} (#{packet})"
        end
      end
    end

    def expect_message(type)
      message = next_message
      unless message.type == type
        raise Net::SSH::Exception, "expected #{type}, got #{message.type} (#{message})"
      end
      message
    end
  end
end; end; end