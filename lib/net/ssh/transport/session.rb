require 'socket'
require 'timeout'

require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/version'
require 'net/ssh/transport/algorithms'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/packet_stream'
require 'net/ssh/transport/server_version'
require 'net/ssh/verifiers/null'
require 'net/ssh/verifiers/strict'
require 'net/ssh/verifiers/lenient'

module Net; module SSH; module Transport
  class Session
    include Constants, Loggable

    DEFAULT_PORT = 22

    attr_reader :host, :port
    attr_reader :socket
    attr_reader :header
    attr_reader :server_version
    attr_reader :algorithms
    attr_reader :host_key_verifier

    def initialize(host, options={})
      self.logger = options[:logger]

      @host = host
      @port = options[:port] || DEFAULT_PORT

      debug { "establishing connection to #{@host}:#{@port}" }
      factory = options[:proxy] || TCPSocket
      @socket = timeout(options[:timeout] || 0) { factory.open(@host, @port) }
      @socket.extend(PacketStream)
      @socket.logger = @logger

      @queue = []

      @host_key_verifier = select_host_key_verifier(options[:paranoid])

      @server_version = ServerVersion.new(socket, logger)

      @algorithms = Algorithms.new(self, options)
      wait { algorithms.initialized? }
    end

    def host_as_string
      @host_as_string ||= begin
        string = "#{host}"
        string = "[#{string}]:#{port}" if port != DEFAULT_PORT
        string
      end
    end

    def close
      socket.cleanup
      socket.close
    end

    def service_request(service)
      msg = Net::SSH::Buffer.new
      msg.write_byte(SERVICE_REQUEST)
      msg.write_string(service)
      msg
    end

    def rekey!
      if !algorithms.pending?
        algorithms.rekey!
        wait { algorithms.initialized? }
      end
    end

    def rekey_as_needed
      return if algorithms.pending?
      socket.if_needs_rekey? { rekey! }
    end

    def peer
      @peer ||= begin
        addr = socket.getpeername
        ip_address = Socket.getnameinfo(addr, Socket::NI_NUMERICHOST | Socket::NI_NUMERICSERV).first
        { :ip => ip_address, :port => @port.to_i, :host => @host, :canonized => host_as_string }
      end
    end

    def next_message
      poll_message(:block)
    end

    def poll_message(mode=:nonblock, consume_queue=true)
      loop do
        if consume_queue && @queue.any? && algorithms.allow?(@queue.first)
          return @queue.shift
        end

        packet = socket.next_packet(mode)
        return nil if packet.nil?

        case packet.type
        when DISCONNECT
          raise Net::SSH::Disconnect, "disconnected: #{packet[:description]} (#{packet[:reason_code]})"

        when IGNORE
          trace { "IGNORE packet recieved: #{packet[:data].inspect}" }

        when UNIMPLEMENTED
          log { "UNIMPLEMENTED: #{packet[:number]}" }

        when DEBUG
          send(packet[:always_display] ? :log : :debug) { packet[:message] }

        when KEXINIT
          algorithms.accept_kexinit(packet)

        else
          return packet if algorithms.allow?(packet)
          push(packet)
        end
      end
    end

    def wait
      loop do
        message = poll_message(:nonblock, false)
        push(message) if message
        break if !block_given? || yield
      end
    end

    def push(packet)
      @queue.push(packet)
    end

    def send_message(message)
      socket.send_packet(message)
    end

    private

      def select_host_key_verifier(paranoid)
        case paranoid
        when true, nil then
          Net::SSH::Verifiers::Lenient.new
        when false then
          Net::SSH::Verifiers::Null.new
        when :very then
          Net::SSH::Verifiers::Strict.new
        else
          if paranoid.respond_to?(:verify)
            paranoid
          else
            raise ArgumentError, "argument to :paranoid is not valid: #{paranoid.inspect}"
          end
        end
      end
  end
end; end; end