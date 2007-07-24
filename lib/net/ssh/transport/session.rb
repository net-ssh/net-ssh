require 'socket'
require 'timeout'

require 'net/ssh/loggable'
require 'net/ssh/version'
require 'net/ssh/transport/algorithms'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/packet_stream'
require 'net/ssh/transport/server_version'

module Net; module SSH; module Transport
  class Session
    include Constants, Loggable

    DEFAULT_PORT = 22

    attr_reader :host, :port
    attr_reader :socket
    attr_reader :header
    attr_reader :server_version
    attr_reader :algorithms

    def initialize(host, options={})
      self.logger = options[:logger]

      @host = host
      @port = options[:port] || DEFAULT_PORT

      debug { "establishing connection to #{@host}:#{@port}" }
      factory = options[:proxy] || TCPSocket
      @socket = timeout(options[:timeout] || 0) { factory.open(@host, @port) }
      @socket.extend(PacketStream)
      @socket.logger = @logger

      @server_version = ServerVersion.new(socket, logger)
      @algorithms = Algorithms.negotiate_via(self)
    end

    def host_as_string
      string = "#{host}"
      string = "[#{string}]:#{port}" if port != DEFAULT_PORT
      string
    end

    def close
      @socket.close
    end

    def service_request(service)
      msg = Net::SSH::Buffer.new
      msg.write_byte(SERVICE_REQUEST)
      msg.write_string(service)
      msg
    end

    def next_message
      poll_message(:block)
    end

    def poll_message(mode=:nonblock)
      loop do
        packet = socket.next_packet(mode)
        return nil if packet.nil?

        trace { "got packet type #{packet.type} len #{packet.length}" }

        case packet.type
        when DISCONNECT
          reason_code = packet.read_long
          description = packet.read_string
          language = packet.read_string
          raise Net::SSH::Transport::Disconnect, "disconnected: #{description} (#{reason_code})"

        when IGNORE
          trace { "IGNORE packet recieved: #{packet.read_string.inspect}" }

        when DEBUG
          always_display = packet.read_bool
          message = packet.read_string
          language = packet.read_string
          send(always_display ? :log : :debug) { message }

        when UNIMPLEMENTED
          number = packet.read_long
          log { "UNIMPLEMENTED: #{number}" }

        else
          return packet
        end
      end
    end

    def send_message(message)
      message = message.to_s
      trace { "sending packet type #{message[0]} len #{message.length}" }
      socket.send_packet(message)
    end
  end
end; end; end