require 'socket'
require 'openssl'
require 'resolv'
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
        # * :ssl_context => the SSL configuration to use for the connection. The
        #   default verifies the proxy's certificate and hostname against the
        #   system trust store. For a self-signed or private CA certificate pass a
        #   context with it in +cert_store+, or, to skip verification and expose
        #   the proxy credentials to a man-in-the-middle, a context with
        #   +verify_mode+ set to OpenSSL::SSL::VERIFY_NONE.
        def initialize(proxy_host, proxy_port = 80, options = {})
          @ssl_context = options.delete(:ssl_context) || default_ssl_context
          super(proxy_host, proxy_port, options)
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
            socket.extend(SSLSocketCompatibility)
            # SNI must not carry an IP address (RFC 6066).
            socket.hostname = proxy_host unless Resolv::AddressRegex.match?(proxy_host)
            begin
              socket.connect
              socket.post_connection_check(proxy_host) if verify_peer?
            rescue StandardError
              socket.close
              raise
            end
          end
        end

        private

        def default_ssl_context
          OpenSSL::SSL::SSLContext.new.tap(&:set_params)
        end

        # verify_mode is nil on a bare SSLContext in older openssl gems.
        def verify_peer?
          @ssl_context.verify_mode.to_i != OpenSSL::SSL::VERIFY_NONE
        end
      end
    end
  end
end
