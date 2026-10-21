# frozen_string_literal: true

require 'io/wait'

require 'net/ssh/buffer'
require 'net/ssh/buffered_io'
require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/packet'
require 'net/ssh/connection/constants'

module Net
  module SSH
    module Multiplex
      # Packet framing on a ControlMaster socket in proxy mode: the usual
      # uint32 packet_length and byte padding_length, but no padding, MAC,
      # encryption or compression. The master parses everything after the
      # padding_length byte as payload (channel_proxy_downstream in OpenSSH's
      # channels.c), so padding must not be sent.
      module PacketSocket
        include BufferedIo

        # OpenSSH's PACKET_MAX_SIZE.
        MAX_PACKET_SIZE = 256 * 1024

        def self.extended(object) # :nodoc:
          object.__send__(:initialize_buffered_io)
        end

        def available_for_read?
          !wait_readable(0).nil?
        end

        # Same contract as Net::SSH::Transport::PacketStream#next_packet.
        def next_packet(mode = :nonblock, timeout = nil)
          case mode
          when :nonblock
            packet = poll_next_packet
            return packet if packet

            if available_for_read? && fill <= 0
              packet = poll_next_packet
              raise Net::SSH::Disconnect, "connection closed by ControlMaster" if packet.nil?

              return packet
            end
            poll_next_packet
          when :block
            loop do
              packet = poll_next_packet
              return packet if packet

              raise Net::SSH::ConnectionTimeout, "timeout waiting for next packet" unless wait_readable(timeout)
              raise Net::SSH::Disconnect, "connection closed by ControlMaster" if fill <= 0
            end
          else
            raise ArgumentError, "expected :block or :nonblock, got #{mode.inspect}"
          end
        end

        def enqueue_packet(payload)
          data = payload.to_s
          enqueue([data.bytesize + 1, 0].pack('NC') + data.b)
        end

        def send_packet(payload)
          enqueue_packet(payload)
          wait_for_pending_sends
        end

        private

        def poll_next_packet
          return nil if available < 4

          start = input.position
          length = input.read_long
          raise Net::SSH::Exception, "invalid packet length #{length} from ControlMaster" unless length.between?(1, MAX_PACKET_SIZE)

          if available < length
            input.position = start
            return nil
          end

          data = input.read(length)
          input.consume!
          padding = data.getbyte(0)
          raise Net::SSH::Exception, "invalid padding length #{padding} from ControlMaster" if padding > length - 2

          Net::SSH::Packet.new(data.byteslice(1, length - 1 - padding))
        end
      end

      # Stands in for Net::SSH::Transport::Session underneath a
      # Net::SSH::Connection::Session when connected through an OpenSSH
      # ControlMaster in proxy mode. Key exchange, rekeying, host key
      # verification and authentication all belong to the master, so the
      # matching transport methods are no-ops or raise
      # NotSupportedOverControlMaster.
      class ProxyTransport
        include Loggable
        include Net::SSH::Connection::Constants

        DEFAULT_PORT = 22

        # Channel requests whose follow-up channel the server opens towards
        # the master, which serves it from its own agent or X display only if
        # it has ForwardAgent or ForwardX11 enabled itself, and rejects it
        # otherwise (clientloop.c, client_input_channel_open).
        UNSUPPORTED_CHANNEL_REQUESTS = %w[auth-agent-req@openssh.com auth-agent-req x11-req].freeze

        attr_reader :host, :port, :socket, :options

        # The ControlMaster socket path this transport is connected through.
        attr_reader :control_path

        def initialize(socket, host:, control_path:, options: {})
          self.logger = options[:logger]
          @host = host
          @port = options[:port] || DEFAULT_PORT
          @options = options
          @control_path = control_path
          @socket = socket
          @socket.extend(PacketSocket)
          @socket.logger = logger
        end

        def host_as_string
          @host_as_string ||= port == DEFAULT_PORT ? host.to_s : "[#{host}]:#{port}"
        end

        def peer
          @peer ||= { ip: nil, port: port.to_i, host: host, canonized: host_as_string }
        end

        def closed?
          socket.closed?
        end

        def close
          socket.close unless closed?
        end

        def shutdown!
          error { "forcing connection closed" }
          close
        end

        def next_message
          poll_message(:block)
        end

        def poll_message(mode = :nonblock, *)
          socket.next_packet(mode, options[:timeout])
        end

        def send_message(message)
          socket.send_packet(check_supported(message.to_s))
        end

        def enqueue_message(message)
          socket.enqueue_packet(check_supported(message.to_s))
        end

        # The master rekeys its own connection.
        def rekey!; end

        def rekey_as_needed; end

        def hint(*); end

        def server_version
          not_supported("the server version")
        end

        def algorithms
          not_supported("the negotiated algorithms")
        end

        def host_keys
          not_supported("the host keys")
        end

        def host_key_verifier
          not_supported("host key verification")
        end

        private

        def not_supported(what)
          raise NotSupportedOverControlMaster, "#{what} belong(s) to the ControlMaster at #{control_path}"
        end

        # The master kills the proxy connection on any global request other
        # than tcpip-forward, and consumes the reply to that one itself, so
        # its success or failure and an allocated port 0 can't be observed
        # (channels.c channel_proxy_downstream, clientloop.c
        # client_global_request_reply).
        def check_supported(data)
          case data.getbyte(0)
          when GLOBAL_REQUEST
            request = Net::SSH::Buffer.new(data.byteslice(1..-1)).read_string
            if request == 'tcpip-forward'
              raise NotSupportedOverControlMaster, "remote forwarding (tcpip-forward) is not supported over a ControlMaster: " \
                                                   "the master consumes the reply, so success and the allocated port can't be observed"
            end

            raise NotSupportedOverControlMaster, "global request #{request} is not supported over a ControlMaster"
          when CHANNEL_REQUEST
            request = Net::SSH::Buffer.new(data.byteslice(5..-1)).read_string
            if UNSUPPORTED_CHANNEL_REQUESTS.include?(request)
              raise NotSupportedOverControlMaster, "channel request #{request} is not supported over a ControlMaster"
            end
          end
          data
        end
      end
    end
  end
end
