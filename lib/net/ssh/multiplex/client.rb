require 'io/wait'
require 'socket'

require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'

module Net
  module SSH
    module Multiplex
      # Raised when the ControlMaster socket can't be used, e.g. the master
      # refused the request or spoke an unexpected protocol.
      class Error < Net::SSH::Exception; end

      # Connects to an OpenSSH ControlMaster's UNIX socket and switches it to
      # proxy mode (MUX_C_PROXY, OpenSSH 7.4 and later), after which the socket
      # carries plain SSH connection-protocol packets. See PROTOCOL.mux and
      # mux.c in OpenSSH.
      class Client
        include Loggable

        MUX_MSG_HELLO = 0x00000001
        MUX_C_PROXY = 0x1000000f
        MUX_S_PERMISSION_DENIED = 0x80000002
        MUX_S_FAILURE = 0x80000003
        MUX_S_PROXY = 0x8000000f

        PROTOCOL_VERSION = 4

        # Mux control messages are small; this only guards against reading a
        # bogus length from something that isn't a ControlMaster.
        MAX_MESSAGE_SIZE = 256 * 1024

        attr_reader :path

        def initialize(path, timeout:, logger: nil)
          self.logger = logger
          @path = path
          @timeout = timeout
        end

        # Performs the HELLO and PROXY exchange and returns the connected
        # socket, positioned at the first proxied packet. Raises
        # Multiplex::Error, SystemCallError or IOError if the master can't be
        # used; the socket is closed in that case.
        def connect_proxy
          @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
          @socket = open_socket
          verify_peer
          hello
          request_proxy
          @socket
        rescue StandardError
          @socket&.close
          raise
        end

        private

        def open_socket
          socket = Socket.new(Socket::AF_UNIX, Socket::SOCK_STREAM)
          address = Socket.sockaddr_un(path)
          loop do
            result = socket.connect_nonblock(address, exception: false)
            break if result == 0

            wait_for(:writable, socket)
          rescue Errno::EISCONN
            break
          end
          socket
        rescue StandardError
          socket&.close
          raise
        end

        # The master itself rejects clients with a different uid (channels.c,
        # getpeereid); checking here also keeps us off a socket someone else
        # planted at the ControlPath.
        def verify_peer
          euid = begin
            @socket.getpeereid.first
          rescue NotImplementedError
            File.stat(path).uid
          end
          raise Error, "#{path} is owned by uid #{euid}, not #{Process.euid}" unless euid == Process.euid
        end

        def hello
          type, body = read_message
          raise Error, "expected MUX_MSG_HELLO, got 0x#{type.to_s(16)}" unless type == MUX_MSG_HELLO

          version = body.read_long
          raise Error, "unsupported mux protocol version #{version}" unless version == PROTOCOL_VERSION

          # Any extensions the master advertises (OpenSSH 10.3 sends "info")
          # are optional, so the rest of the body is ignored.
          write_message(MUX_MSG_HELLO, :long, PROTOCOL_VERSION)
          debug { "mux hello exchanged with #{path}" }
        end

        def request_proxy
          request_id = 1
          write_message(MUX_C_PROXY, :long, request_id)
          type, body = read_message
          case type
          when MUX_S_PROXY
            reply_id = body.read_long
            raise Error, "MUX_S_PROXY for request #{reply_id}, expected #{request_id}" unless reply_id == request_id
          when MUX_S_PERMISSION_DENIED, MUX_S_FAILURE
            body.read_long
            raise Error, "master refused proxy request: #{body.read_string}"
          else
            raise Error, "unexpected reply 0x#{type.to_s(16)} to MUX_C_PROXY"
          end
        end

        def write_message(type, *args)
          body = Net::SSH::Buffer.from(:long, type, *args).to_s
          data = [body.bytesize].pack('N') + body
          until data.empty?
            written = @socket.write_nonblock(data, exception: false)
            if written == :wait_writable
              wait_for(:writable, @socket)
            else
              data = data.byteslice(written..-1)
            end
          end
        end

        def read_message
          length = read_exactly(4).unpack1('N')
          raise Error, "mux message length #{length} out of range" unless length.between?(4, MAX_MESSAGE_SIZE)

          body = Net::SSH::Buffer.new(read_exactly(length))
          [body.read_long, body]
        end

        # Reads exactly +count+ bytes so nothing after the PROXY reply, which
        # already belongs to the packet stream, is consumed here.
        def read_exactly(count)
          data = String.new(encoding: Encoding::BINARY)
          while data.bytesize < count
            chunk = @socket.read_nonblock(count - data.bytesize, exception: false)
            case chunk
            when :wait_readable then wait_for(:readable, @socket)
            when nil then raise Error, "#{path} closed the connection during the mux handshake"
            else data << chunk
            end
          end
          data
        end

        def wait_for(direction, socket)
          remaining = @deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          ready = remaining > 0 && (direction == :readable ? socket.wait_readable(remaining) : socket.wait_writable(remaining))
          raise Error, "timed out talking to #{path}" unless ready
        end
      end
    end
  end
end
