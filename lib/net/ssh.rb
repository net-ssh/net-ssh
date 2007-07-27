require 'logger'

require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/transport/session'
require 'net/ssh/authentication/session'
require 'net/ssh/connection/session'

module Net
  module SSH
    def self.start(host, user, options={}, &block)
      if !options.key?(:logger)
        options[:logger] = Logger.new(STDERR)
        options[:logger].level = Logger::WARN
      end

      options[:logger].level = options[:verbose] if options[:verbose]

      transport = Transport::Session.new(host, options)
      auth = Authentication::Session.new(transport, options)

      if auth.authenticate("ssh-connection", user, options[:password])
        connection = Connection::Session.new(transport, options)
        if block_given?
          yield connection
          connection.close
        else
          return connection
        end
      else
        raise AuthenticationFailed, user
      end
    end
  end
end