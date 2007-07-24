require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/authentication/constants'

module Net; module SSH; module Authentication; module Methods

  class Abstract
    include Constants, Loggable

    attr_reader :session, :key_manager

    def initialize(session, options={})
      @session = session
      @key_manager = options[:key_manager]
      self.logger = session.logger
    end

    def session_id
      session.transport.algorithms.session_id
    end

    def send_message(msg)
      session.transport.send_message(msg)
    end

    def userauth_request(username, next_service, auth_method, *others)
      buffer = Net::SSH::Buffer.new
      buffer.write_byte(USERAUTH_REQUEST)
      buffer.write_string(username)
      buffer.write_string(next_service)
      buffer.write_string(auth_method)

      others.each do |value|
        case value
        when true, false then buffer.write_bool(value)
        when String      then buffer.write_string(value)
        else raise ArgumentError, "don't know how to write #{value.inspect}"
        end
      end

      buffer
    end
end

end; end; end; end