require 'logger'

require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/transport/session'
require 'net/ssh/authentication/session'
require 'net/ssh/connection/session'

module Net
  module SSH
    VALID_OPTIONS = [
      :auth_methods, :compression, :compression_level, :encryption,
      :forward_agent, :hmac, :host_key, :kex, :keys, :languages,
      :logger, :paranoid, :password, :port, :proxy, :rekey_blocks_limit,
      :rekey_limit, :rekey_packet_limit, :timeout, :verbose
    ]

    def self.start(host, user, options={}, &block)
      invalid_options = options.keys - VALID_OPTIONS
      if invalid_options.any?
        raise ArgumentError, "invalid option(s): #{invalid_options.join(', ')}"
      end

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