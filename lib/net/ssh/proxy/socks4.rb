require 'socket'
require 'resolv'
require 'ipaddr'
require 'net/ssh/proxy/errors'

module Net
  module SSH
    module Proxy

      # An implementation of a socket factory that returns a socket which
      # will tunnel the connection through a SOCKS4 proxy. It allows explicit
      # specification of the user.
      class SOCKS4

        VERSION = 4
        CONNECT = 1
        GRANTED = 90

        attr_reader :proxy_host, :proxy_port
        attr_reader :options

        # Create a new proxy connection to the given proxy host and port.
        # Optionally, a @:user@ option may be given to identify the username
        # with which to authenticate.
        def initialize(proxy_host, proxy_port=1080, options={})
          @proxy_host = proxy_host
          @proxy_port = proxy_port
          @options = options
        end

        # Return a new socket connected to the given host and port via the
        # proxy that was requested when the socket factory was instantiated.
        def open(host, port)
          socket = TCPSocket.new(proxy_host, proxy_port)
          ip_addr = IPAddr.new(Resolv.getaddress(host))
          
          packet = [VERSION, CONNECT, port.to_i, ip_addr.to_i, options[:user]].pack("CCnNZ*")
          socket.send packet, 0

          version, status, port, ip = socket.recv(8).unpack("CCnN")
          if status != GRANTED
            socket.close
            raise ConnectError, "error connecting to proxy (#{status})"
          end

          return socket
        end

      end

    end
  end
end
