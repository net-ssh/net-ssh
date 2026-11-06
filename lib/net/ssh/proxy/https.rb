require 'socket'
require 'openssl'
require 'net/ssh/proxy/errors'
require 'net/ssh/proxy/http'

module Net
  module SSH
    module Proxy
      # A specialization of the HTTP proxy which encrypts the whole connection
      # using OpenSSL. This has the advantage that proxy authentication
      # information is not sent in plaintext.
      class HTTPS < HTTP
        # Create a new socket factory that tunnels via the given host and
        # port. The +options+ parameter is a hash of additional settings that
        # can be used to tweak this proxy connection. In addition to the options
        # taken by Net::SSH::Proxy::HTTP it supports:
        #
        # * :ssl_context => the SSL configuration to use for the connection
        def initialize(proxy_host, proxy_port = 80, options = {})
          @ssl_context = options.delete(:ssl_context) || self.class.default_ssl_context
          super(proxy_host, proxy_port, options)
        end

        # Builds the SSL context used when the caller does not supply one. Unlike a
        # bare OpenSSL::SSL::SSLContext.new (which defaults to VERIFY_NONE and does
        # no hostname checking), this enables peer verification against the system
        # trust store so proxy credentials are not exposed to a man-in-the-middle.
        def self.default_ssl_context
          OpenSSL::SSL::SSLContext.new.tap(&:set_params)
        end

        protected

        # Shim to make OpenSSL::SSL::SSLSocket behave like a regular TCPSocket
        # for all intents and purposes of Net::SSH::BufferedIo
        module SSLSocketCompatibility
          def self.extended(object) # :nodoc:
            object.define_singleton_method(:recv, object.method(:sysread))
            object.sync_close = true
          end

          def send(data, _opts)
            syswrite(data)
          end
        end

        def establish_connection(connect_timeout)
          plain_socket = super(connect_timeout)
          OpenSSL::SSL::SSLSocket.new(plain_socket, @ssl_context).tap do |socket|
            socket.hostname = proxy_host if socket.respond_to?(:hostname=)
            socket.extend(SSLSocketCompatibility)
            socket.connect
            socket.post_connection_check(proxy_host) if verify?(socket)
          end
        end

        # Whether the negotiated context actually verifies the peer. When it does
        # we also enforce hostname matching; when the caller deliberately opted
        # into VERIFY_NONE we leave their choice untouched.
        def verify?(socket)
          mode = socket.context.verify_mode
          !mode.nil? && mode != OpenSSL::SSL::VERIFY_NONE
        end
      end
    end
  end
end
