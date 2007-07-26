require 'net/ssh/loggable'
require 'net/ssh/connection/constants'

module Net; module SSH; module Connection

  class Channel
    include Constants, Loggable

    attr_reader :local_id
    attr_reader :remote_id
    attr_reader :type
    attr_reader :connection

    attr_reader :local_maximum_packet_size
    attr_reader :local_maximum_window_size
    attr_reader :remote_maximum_packet_size
    attr_reader :remote_maximum_window_size

    attr_reader :local_window_size
    attr_reader :remote_window_size

    attr_reader :output
    attr_reader :properties

    def initialize(connection, type, local_id, &on_confirm_open)
      self.logger = connection.logger

      @connection = connection
      @type       = type
      @local_id   = local_id

      @local_maximum_packet_size = 0x10000
      @local_window_size = @local_maximum_window_size = 0x20000

      @on_confirm_open = on_confirm_open

      @output = Buffer.new

      @properties = {}

      @on_data = @on_process = @on_close = nil
      @closing = false
    end

    def [](name)
      @properties[name]
    end

    def []=(name, value)
      @properties[name] = value
    end

    def exec(command, want_reply=false)
      connection.send_message(channel_request("exec", command, want_reply))
    end

    def send_data(data)
      output.append(data)
    end

    def closing?
      @closing
    end

    def close
      return if @closing
      @closing = true
      connection.send_message(Buffer.from(:byte, CHANNEL_CLOSE, :long, remote_id))
    end

    def important?
      true
    end

    def process
      @on_process.call(self) if @on_process
      enqueue_pending_output
    end
  
    def enqueue_pending_output
      return unless remote_id

      length = output.length
      length = remote_window_size if length > remote_window_size
      length = remote_maximum_packet_size if length > remote_maximum_packet_size

      if length > 0
        connection.send_message(Buffer.from(:byte, CHANNEL_DATA, :long, remote_id, :string, output.read(length)))
        output.consume!
        @remote_window_size -= length
      end
    end

    def on_data(&block)
      @on_data = block
    end

    def on_process(&block)
      @on_process = block
    end

    def on_close(&block)
      @on_close = block
    end

    def channel_request(request_name, data, want_reply=false)
      Buffer.from(:byte, CHANNEL_REQUEST,
        :long, remote_id, :string, request_name,
        :bool, want_reply, :string, data)
    end

    def do_open_confirmation(remote_id, max_window, max_packet)
      @remote_id = remote_id
      @remote_window_size = @remote_maximum_window_size = max_window
      @remote_maximum_packet_size = max_packet
      @on_confirm_open.call(self) if @on_confirm_open
    end

    def do_window_adjust(bytes)
      @remote_maximum_window_size += bytes
      @remote_window_size += bytes
    end

    def do_request(request, want_reply, data)
      # ...
    end

    def do_data(data)
      update_local_window_size(data.length)
      @on_data.call(self, data) if @on_data
    end

    def do_eof
    end

    def do_close
      @on_close.call(self) if @on_close
    end

    private

      def update_local_window_size(size)
        @local_window_size -= size
        if local_window_size < local_maximum_window_size/2
          connection.send_message(Buffer.from(:byte, CHANNEL_WINDOW_ADJUST,
            :long, remote_id, :long, 0x20000))
          @local_window_size += 0x20000
          @local_maximum_window_size += 0x20000
        end
      end
  end

end; end; end