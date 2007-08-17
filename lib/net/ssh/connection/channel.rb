require 'net/ssh/loggable'
require 'net/ssh/connection/constants'
require 'net/ssh/connection/term'

module Net; module SSH; module Connection

  # The channel abstraction. Multiple "channels" can be multiplexed onto a
  # single SSH channel, each operating independently and seemingly in parallel.
  # This class represents a single such channel. Most operations performed
  # with the Net::SSH library will involve using one or more channels.
  #
  # Channels are intended to be used asynchronously. You request that one be
  # opened (via Connection::Session#open_channel), and when it is opened, your
  # callback is invoked. Then, you set various other callbacks on the newly
  # opened channel, which are called in response to the corresponding events.
  # Programming with Net::SSH works best if you think of your programs as
  # state machines. Complex programs are best implemented as objects that
  # wrap a channel. See Net::SCP and Net::SFTP for examples.
  class Channel
    include Constants, Loggable

    # The local id for this channel, assigned by the Connection::Session instance.
    attr_reader :local_id

    # The remote id for this channel, assigned by the remote host.
    attr_reader :remote_id

    # The type of this channel, usually "session".
    attr_reader :type

    # The underlying Connection::Session instance that supports this channel.
    attr_reader :connection

    # The maximum packet size that the local host can receive.
    attr_reader :local_maximum_packet_size

    # The maximum amount of data that the local end of this channel can
    # receive. This is a total, not per-packet.
    attr_reader :local_maximum_window_size

    # The maximum packet size that the remote host can receive.
    attr_reader :remote_maximum_packet_size

    # The maximum amount of data that the remote end of this channel can
    # receive. This is a total, not per-packet.
    attr_reader :remote_maximum_window_size

    # This is the remaining window size on the local end of this channel. When
    # this reaches zero, no more data can be received.
    attr_reader :local_window_size

    # This is the remaining window size on the remote end of this channel. When
    # this reaches zero, no more data can be sent.
    attr_reader :remote_window_size

    # A hash of properties for this channel. These can be used to store state
    # information about this channel. See also #[] and #[]=.
    attr_reader :properties

    # The output buffer for this channel. Data written to the channel is
    # enqueued here, to be written as CHANNEL_DATA packets during each pass of
    # the event loop. See Connection::Session#process and #enqueue_pending_output.
    attr_reader :output #:nodoc:

    # The list of pending requests. Each time a request is sent which requires
    # a reply, the corresponding callback is pushed onto this queue. As responses
    # arrive, they are shifted off the front and handled.
    attr_reader :pending_requests #:nodoc:

    # Instantiates a new channel on the given connection, of the given type,
    # and with the given id. If a block is given, it will be remembered until
    # the channel is confirmed open by the server, and will be invoked at
    # that time (see #do_open_confirmation).
    #
    # This also sets the default maximum packet size and maximum window size.
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
      @on_data = @on_extended_data = @on_process = @on_close = @on_eof = nil
      @on_request = {}
      @closing = false
    end

    # A shortcut for accessing properties of the channel (see #properties).
    def [](name)
      @properties[name]
    end

    # A shortcut for setting properties of the channel (see #properties).
    def []=(name, value)
      @properties[name] = value
    end

    # Syntactic sugar for executing a command. Sends a channel request asking
    # that the given command be invoked. If the block is given, it will be
    # called when the server responds. The first parameter will be the
    # channel, and the second will be true or false, indicating whether the
    # request succeeded or not. In this case, success means that the command
    # is being executed, not that it has completed, and failure means that the
    # command altogether failed to be executed.
    def exec(command, &block)
      send_channel_request("exec", :string, command, &block)
    end

    # Syntactic sugar for requesting that a subsystem be started. Subsystems
    # are a way for other protocols (like SFTP) to be run, using SSH as
    # the transport. Generally, you'll never need to call this directly unless
    # you are the implementor of a subsystem.
    def subsystem(subsystem, &block)
      send_channel_request("subsystem", :string, subsystem, &block)
    end

    # A hash of the valid PTY options.
    VALID_PTY_OPTIONS = { :term=>"xterm",
                          :chars_wide=>80,
                          :chars_high=>24,
                          :pixels_wide=>640,
                          :pixels_high=>480,
                          :modes=>{} }

    # Requests that a pty be made available for this channel. This is useful
    # when you want to invoke and interact with some kind of screen-based
    # program (e.g., vim, or some menuing system).
    def request_pty(opts={}, &block)
      extra = opts.keys - VALID_PTY_OPTIONS.keys
      raise ArgumentError, "invalid option(s) to request_pty: #{extra.inspect}" if extra.any?

      opts = VALID_PTY_OPTIONS.merge(opts)

      modes = opts[:modes].inject([]) do |memo, (mode, data)|
        memo << :byte << mode
        memo << :long << data
      end
      modes << :byte << Term::TTY_OP_END
      modes = Buffer.from(*modes).to_s

      send_channel_request("pty-req", :string, opts[:term],
        :long, opts[:chars_wide], :long, opts[:chars_high],
        :long, opts[:pixels_wide], :long, opts[:pixels_high],
        :string, modes, &block)
    end

    # Appends the given data to the channel's output buffer, preparatory to
    # being packaged up and sent to the remote server as channel data.
    def send_data(data)
      output.append(data.to_s)
    end

    # Returns true if the channel is currently closing, but not actually
    # closed. A channel is closing when, for instance, #close has been
    # invoked, but the server has not yet responded with a CHANNEL_CLOSE
    # packet of its own.
    def closing?
      @closing
    end

    # Requests that the channel be closed. If the channel is already closing,
    # this does nothing, nor does it do anything if the channel has not yet
    # been confirmed open (see #do_open_confirmation). Otherwise, it sends a
    # CHANNEL_CLOSE message and marks the channel as closing.
    def close
      return if @closing
      if remote_id
        @closing = true
        connection.send_message(Buffer.from(:byte, CHANNEL_CLOSE, :long, remote_id))
      end
    end

    # If an #on_process handler has been set up, this will cause it to be
    # invoked (passing the channel itself as an argument). It also causes all
    # pending output to be enqueued as CHANNEL_DATA packets (see #enqueue_pending_output).
    def process
      @on_process.call(self) if @on_process
      enqueue_pending_output
    end

    # Registers callback to be invoked when data packets are received by the
    # channel. The callback is called with the channel as the first argument,
    # and the data as the second.
    def on_data(&block)
      old, @on_data = @on_data, block
      old
    end

    # Registers callback to be invoked when extended data packets are received
    # by the channel. The callback is called with the channel as the first
    # argument, the data type (as an integer) as the second, and the data as
    # the third. Extended data is almost exclusively used to send STDERR data.
    def on_extended_data(&block)
      old, @on_extended_data = @on_extended_data, block
      old
    end

    # Registers a callback to be invoked for each pass of the event loop for
    # this channel. There are no guarantees on timeliness in the event loop,
    # but it will be called roughly once for each packet received by the
    # connection (not the channel). This callback is invoked with the channel
    # as the sole argument.
    def on_process(&block)
      old, @on_process = @on_process, block
      old
    end

    # Registers a callback to be invoked when the server acknowledges that a
    # channel is closed. This is invoked with the channel as the sole argument.
    def on_close(&block)
      old, @on_close = @on_close, block
      old
    end

    # Registers a callback to be invoked when the server indicates that no more
    # data will be sent to the channel (although the channel can still send
    # data to the server). The channel is the sole argument to the callback.
    def on_eof(&block)
      old, @on_eof = @on_eof, block
      old
    end

    # Registers a callback to be invoked when a channel request of the given
    # type is received. The callback will receive the channel as the first
    # argument, and the associated data as the second. By default, if the request
    # wants a reply, Net::SSH will send a CHANNEL_SUCCESS response for any
    # request that was handled by a registered callback, and CHANNEL_FAILURE
    # for any that wasn't, but if you want your registered callback to result
    # in a CHANNEL_FAILURE response, just raise ChannelRequestFailed.
    def on_request(type, &block)
      old, @on_request[type] = @on_request[type], block
      old
    end

    # Sends a new channel request with the given name. The extra +data+
    # parameter must either be empty, or consist of an even number of
    # arguments. See Net::SSH::Buffer.from for a description of their format.
    # If a block is given, it is registered as a callback for a pending
    # request, and the packet will be flagged so that the server knows a
    # reply is required. If no block is given, the server will send no
    # response to this request. Responses, where required, will cause the
    # callback to be invoked with the channel as the first argument, and
    # either true or false as the second, depending on whether the request
    # succeeded or not. The meaning of "success" and "failure" in this context
    # is dependent on the specific request that was sent.
    def send_channel_request(request_name, *data, &callback)
      msg = Buffer.from(:byte, CHANNEL_REQUEST,
        :long, remote_id, :string, request_name,
        :bool, !callback.nil?, *data)
      connection.send_message(msg)
      pending_requests << callback if callback
    end

    public # these methods are public, but for internal use only

      # Enqueues pending output at the connection as CHANNEL_DATA packets. This
      # does nothing if the channel has not yet been confirmed open (see
      # #do_open_confirmation). This is called automatically by #process, which
      # is called from the event loop (Connection::Session#process). You will
      # generally not need to invoke it directly.
      def enqueue_pending_output #:nodoc:
        return unless remote_id

        while output.length > 0
          length = output.length
          length = remote_window_size if length > remote_window_size
          length = remote_maximum_packet_size if length > remote_maximum_packet_size

          if length > 0
            connection.send_message(Buffer.from(:byte, CHANNEL_DATA, :long, remote_id, :string, output.read(length)))
            output.consume!
            @remote_window_size -= length
          else
            break
          end
        end
      end

      # Invoked when the server confirms that a channel has been opened.
      # The remote_id is the id of the channel as assigned by the remote host,
      # and max_window and max_packet are the maximum window and maximum
      # packet sizes, respectively. If an open-confirmation callback was
      # given when the channel was created, it is invoked at this time with
      # the channel itself as the sole argument.
      def do_open_confirmation(remote_id, max_window, max_packet) #:nodoc:
        @remote_id = remote_id
        @remote_window_size = @remote_maximum_window_size = max_window
        @remote_maximum_packet_size = max_packet
        connection.forward.agent(self) if connection.options[:forward_agent] && type == "session"
        @on_confirm_open.call(self) if @on_confirm_open
      end

      # Invoked when the server sends a CHANNEL_WINDOW_ADJUST packet, and
      # causes the remote window size to be adjusted upwards by the given
      # number of bytes. This has the effect of allowing more data to be sent
      # from the local end to the remote end of the channel.
      def do_window_adjust(bytes) #:nodoc:
        @remote_maximum_window_size += bytes
        @remote_window_size += bytes
      end

      # Invoked when the server sends a channel request. If any #on_request
      # callback has been registered for the specific type of this request,
      # it is invoked. If +want_reply+ is true, a packet will be sent of
      # either CHANNEL_SUCCESS or CHANNEL_FAILURE type. If there was no callback
      # to handle the request, CHANNEL_FAILURE will be sent. Otherwise,
      # CHANNEL_SUCCESS, unless the callback raised ChannelRequestFailed. The
      # callback should accept the channel as the first argument, and the
      # request-specific data as the second.
      def do_request(request, want_reply, data) #:nodoc:
        result = true

        begin
          callback = @on_request[request] or raise ChannelRequestFailed
          callback.call(self, data)
        rescue ChannelRequestFailed
          result = false
        end

        if want_reply
          msg = Buffer.from(:byte, result ? CHANNEL_SUCCESS : CHANNEL_FAILURE, :long, remote_id)
          connection.send_message(msg)
        end
      end

      # Invokes the #on_data callback when the server sends data to the
      # channel. This will reduce the available window size on the local end,
      # but does not actually throttle requests that come in illegally when
      # the window size is too small. The callback is invoked with the channel
      # as the first argument, and the data as the second.
      def do_data(data) #:nodoc:
        update_local_window_size(data.length)
        @on_data.call(self, data) if @on_data
      end

      # Invokes the #on_extended_data callback when the server sends
      # extended data to the channel. This will reduce the available window
      # size on the local end. The callback is invoked with the channel,
      # type, and data.
      def do_extended_data(type, data)
        update_local_window_size(data.length)
        @on_extended_data.call(self, type, data) if @on_extended_data
      end

      # Invokes the #on_eof callback when the server indicates that no
      # further data is forthcoming. The callback is invoked with the channel
      # as the argument.
      def do_eof
        @on_eof.call(self) if @on_eof
      end

      # Invokes the #on_close callback when the server closes a channel.
      # The channel is the only argument.
      def do_close
        @on_close.call(self) if @on_close
      end

      # Invokes the next pending request callback with +false+ as the second
      # argument.
      def do_failure
        if callback = pending_requests.shift
          callback.call(self, false)
        else
          error { "channel failure recieved with no pending request to handle it (bug?)" }
        end
      end

      # Invokes the next pending request callback with +true+ as the second
      # argument.
      def do_success
        if callback = pending_requests.shift
          callback.call(self, true)
        else
          error { "channel success recieved with no pending request to handle it (bug?)" }
        end
      end

    private

      # Updates the local window size by the given amount. If the window
      # size drops to less than half of the local maximum (an arbitrary
      # threshold), a CHANNEL_WINDOW_ADJUST message will be sent to the
      # server telling it that the window size has grown.
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