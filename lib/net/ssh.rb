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

    # The standard means of starting a new SSH connection. When used with a
    # block, the connection will be closed when the block terminates, otherwise
    # the connection will just be returned.
    #
    # This method accepts the following options (all are optional):
    #
    # * :auth_methods => an array of authentication methods to try
    # * :compression => the compression algorithm to use, or +true+ to use whatever is supported.
    # * :compression_level => the compression level to use when sending data
    # * :encryption => the encryption cipher to use
    # * :forward_agent => set to true if you want the SSH agent connection to be forwarded
    # * :hmac => the hmac algorithm to use
    # * :kex => the key exchange algorithm to use
    # * :keys => an array of file names of private keys to use for publickey and hostbased authentication
    # * :logger => the logger instance to use when logging
    # * :paranoid => either true, false, or :very, specifying how strict host-key verification should be
    # * :password => the password to use to login
    # * :port => the port to use when connecting to the reote host
    # * :proxy => a proxy instance (see Proxy) to use when connecting
    # * :rekey_blocks_limit => the max number of blocks to process before rekeying
    # * :rekey_limit => the max number of bytes to process before rekeying
    # * :rekey_packet_limit => the max number of packets to process before rekeying
    # * :timeout => how long to wait for the initial connection to be made
    # * :verbose => how verbose to be (0 is very verbose, 4 is not very verbose)
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