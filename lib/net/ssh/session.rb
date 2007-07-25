require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/transport/session'
require 'net/ssh/authentication/session'
require 'net/ssh/connection/session'

module Net; module SSH

  class Session
    include Loggable

    attr_reader :transport
    attr_reader :connection

    def initialize(host, options={})
      self.logger = options[:logger]

      @transport = Transport::Session.new(host, options)

      auth = Authentication::Session.new(@transport, options)
      if auth.authenticate("ssh-connection", options[:username], options[:password])
        @connection = Connection::Session.new(@transport, options)
      else
        raise AuthenticationFailed, options[:username]
      end
    end

    def close
      @transport.close
    end
  end

end; end