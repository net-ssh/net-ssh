require 'socket'
require 'net/ssh/proxy/errors'

module Net
  module SSH
    module Proxy

      # An implementation of a socket factory that returns a socket which
      # will tunnel the connection through a SOCKS5 proxy. It allows explicit
      # specification of the user and password.
      class SOCKS5
        VERSION        = 5
        METHOD_NO_AUTH = 0
        METHOD_PASSWD  = 2
        METHOD_NONE    = 0xFF
        CMD_CONNECT    = 1
        ATYP_IPV4      = 1
        ATYP_DOMAIN    = 3
        SUCCESS        = 0

        attr_reader :proxy_host, :proxy_port
        attr_reader :options

        # Create a new proxy connection to the given proxy host and port.
        # Optionally, @:user@ and @:password@ options may be given to
        # identify the username and password with which to authenticate.
        def initialize(proxy_host, proxy_port=1080, options={})
          @proxy_host = proxy_host
          @proxy_port = proxy_port
          @options = options
        end

        # Return a new socket connected to the given host and port via the
        # proxy that was requested when the socket factory was instantiated.
        def open(host, port)
          socket = TCPSocket.new(proxy_host, proxy_port)

          methods = [METHOD_NO_AUTH]
          methods << METHOD_PASSWD if options[:user]

          packet = [VERSION, methods.size, *methods].pack("C*")
          socket.send packet, 0

          version, method = socket.recv(2).unpack("CC")
          if version != VERSION
            socket.close
            raise Net::SSH::Proxy::Error, "invalid SOCKS version (#{version})"
          end

          if method == METHOD_NONE
            socket.close
            raise Net::SSH::Proxy::Error, "no supported authorization methods"
          end

          negotiate_password(socket) if method == METHOD_PASSWD

          packet = [VERSION, CMD_CONNECT, 0].pack("C*")

          if host =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/
            packet << [ATYP_IPV4, $1.to_i, $2.to_i, $3.to_i, $4.to_i].pack("C*")
          else
            packet << [ATYP_DOMAIN, host.length, host].pack("CCA*")
          end

          packet << [port].pack("n")
          sockry.send packet, 0

          version, reply, = socket.recv(4).unpack("C*")
          len = socket.recv(1)[0]
          socket.recv(len + 2)

          unless reply == SUCCESS
            socket.close
            raise ConnectError, "#{reply}"
          end

          return socket
        end

        private

          # Simple username/password negotiation with the SOCKS5 server.
          def negotiate_password(socket)
            packet = [0x01, options[:user].length, options[:user],
              options[:password].length, options[:password]].pack("CCA*CA*")
            socket.send packet, 0

            version, status = socket.recv(2).unpack("CC")

            if status != SUCCESS
              socket.close
              raise UnauthorizedError, "could not authorize user"
            end
          end
      end

    end
  end
end
