require 'socket'
require 'net/ssh/proxy/errors'

module Net; module SSH; module Proxy

  # An implementation of a socket factory that returns a socket which
  # will tunnel the connection through an HTTP proxy. It allows explicit
  # specification of the user and password, but if none are given it
  # will look in the HTTP_PROXY_USER/HTTP_PROXY_PASSWORD and
  # CONNECT_USER/CONNECT_PASSWORD environment variables as well.
  class HTTP

    attr_reader :proxy_host, :proxy_port
    attr_reader :options

    # Create a new socket factory that tunnels via the given host and
    # port.
    def initialize(proxy_host, proxy_port=80, options={})
      @proxy_host = proxy_host
      @proxy_port = proxy_port
      @options = options
    end

    # Return a new socket connected to the given host and port via the
    # proxy that was requested when the socket factory was instantiated.
    def open(host, port)
      socket = TCPSocket.new(proxy_host, proxy_port)
      socket.write "CONNECT #{host}:#{port} HTTP/1.0\r\n"

      if options[:user]
        credentials = ["#{options[:user]}:#{options[:password]}"].pack("m*").gsub(/\s/, "")
        socket.write "Proxy-Authorization: Basic #{credentials}\r\n"
      end

      socket.write "\r\n"

      resp = parse_response(socket)

      return socket if resp[:code] == 200

      socket.close
      raise ConnectError, resp.inspect
    end

    private

      def parse_response(socket)
        version, code, reason = socket.gets.chomp.split(/ /, 3)
        headers = {}

        while (line = socket.gets.chomp) != ""
          name, value = line.split(/:/, 2)
          headers[name.strip] = value.strip
        end

        if headers["Content-Length"]
          body = socket.read(headers["Content-Length"].to_i)
        end

        return { :version => version,
                 :code => code.to_i,
                 :reason => reason,
                 :headers => headers,
                 :body => body }
      end

  end

end; end; end
