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

    attr_reader :pending_requests

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

      @pending_requests = []
      @on_data = @on_process = @on_close = @on_eof = nil
      @closing = false
    end

    def [](name)
      @properties[name]
    end

    def []=(name, value)
      @properties[name] = value
    end

    def exec(command, &block)
      send_channel_request("exec", command, &block)
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

    %w(data process close eof request).each do |callback|
      class_eval(<<-CODE, __FILE__, __LINE__+1)
        def on_#{callback}(&block)
          old, @on_#{callback} = @on_#{callback}, block
          old
        end
      CODE
    end

    def send_channel_request(request_name, data=nil, &callback)
      msg = Buffer.from(:byte, CHANNEL_REQUEST,
        :long, remote_id, :string, request_name,
        :bool, !callback.nil?)
      msg.write_string(data) if data
      connection.send_message(msg)
      pending_requests << callback if callback
    end

    def do_open_confirmation(remote_id, max_window, max_packet)
      @remote_id = remote_id
      @remote_window_size = @remote_maximum_window_size = max_window
      @remote_maximum_packet_size = max_packet
      # FIXME only request agent forwarding if it has been requested by the user
      connection.forward.agent(self) if type == "session"
      @on_confirm_open.call(self) if @on_confirm_open
    end

    def do_window_adjust(bytes)
      @remote_maximum_window_size += bytes
      @remote_window_size += bytes
    end

    def do_request(request, want_reply, data)
      @on_request.call(self, request, want_reply, data) if @on_request
    end

    def do_data(data)
      update_local_window_size(data.length)
      @on_data.call(self, data) if @on_data
    end

    def do_extended_data(type, data)
      # FIXME does the window size need to include the 'type' byte?
      update_local_window_size(data.length)
      @on_extended_data.call(self, data) if @on_extended_data
    end

    def do_eof
      @on_eof.call(self) if @on_eof
    end

    def do_close
      @on_close.call(self) if @on_close
    end

    def do_failure
      if callback = pending_requests.shift
        callback.call(self, false)
      else
        error { "channel failure recieved with no pending request to handle it (bug?)" }
      end
    end

    def do_success
      if callback = pending_requests.shift
        callback.call(self, true)
      else
        error { "channel success recieved with no pending request to handle it (bug?)" }
      end
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