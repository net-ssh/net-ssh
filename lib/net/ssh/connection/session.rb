require 'net/ssh/loggable'
require 'net/ssh/connection/channel'
require 'net/ssh/connection/constants'
require 'net/ssh/service/forward'

module Net; module SSH; module Connection

  # A session class representing the connection service running on top of
  # the SSH transport layer. It manages the creation of channels, and the
  # dispatching of messages to the various channels. It also encapsulates
  # the SSH event loop (via Session#loop and Session#process), and serves
  # as a central point-of-reference for all SSH-related services (e.g.
  # port forwarding, SFTP, SCP, etc.).
  class Session
    include Constants, Loggable

    MAP = Constants.constants.inject({}) do |memo, name|
      value = const_get(name)
      next unless Integer === value
      memo[value] = name.downcase.to_sym
      memo
    end

    # The underlying transport layer abstraction
    attr_reader :transport

    # The map of channels, each key being the local-id for the channel.
    attr_reader :channels

    # The map of listeners that the event loop knows about. See #listen_to.
    attr_reader :listeners

    # The list of callbacks for pending requests. See #send_global_request.
    attr_reader :pending_requests

    # The list of reader IO's that the event loop knows about. See #listen_to.
    attr_reader :readers

    # The list of writer IO's that the event loop knows about. See #listen_to.
    attr_reader :writers

    # The map of specialized handlers for opening specific channel types. See
    # #on_open_channel.
    attr_reader :channel_open_handlers

    # The map of options that were used to initialize this instance.
    attr_reader :options

    # Create a new connection service instance atop the given transport
    # layer. Initializes the readers and writers to be only the underlying
    # socket object.
    def initialize(transport, options={})
      self.logger = transport.logger

      @transport = transport
      @options = options

      @channel_id_counter = -1
      @channels = {}
      @listeners = {}
      @pending_requests = []
      @readers = [transport.socket]
      @writers = [transport.socket]
      @channel_open_handlers = {}
      @on_global_request = {}
    end

    # Closes the session gracefully, blocking until all channels have
    # successfully closed, and then closes the underlying transport layer
    # connection.
    def close
      debug { "closing remaining channels (#{channels.length} open)" }
      channels.each { |id, channel| channel.close }
      loop(0) { channels.any? }
      transport.close
    end

    # preserve a reference to Kernel#loop
    alias :loop_forever :loop

    # The main event loop. Calls #process until #process returns false. If a
    # block is given, it is passed to #process, otherwise a default proc is
    # used that just returns true if there are any channels active. The +wait+
    # parameter is also passed through to #process.
    def loop(wait=nil, &block)
      running = block || Proc.new { channels.any? { |id,ch| !ch[:invisible] } }
      loop_forever { break unless process(wait, &running) }
    end

    # The core of the event loop. It processes a single iteration of the event
    # loop. If a block is given, it should return false when the processing
    # should abort, which causes #process to return false. Otherwise,
    # #process returns true.
    #
    # If +wait+ is nil (the default), this method will block until any of the
    # monitored IO objects are ready to be read from or written to. If you want
    # it to not block, you can pass 0, or you can pass any other numeric value
    # to indicate that it should block for no more than that many seconds.
    #
    # This will cause all active channels to be processed once each.
    def process(wait=nil)
      return false if block_given? && !yield

      dispatch_incoming_packets
      channels.each { |id, channel| channel.process unless channel.closing? }

      return false if block_given? && !yield

      w = writers.select { |w| w.pending_write? }
      ready_readers, ready_writers, = IO.select(readers, w, nil, wait)

      (ready_readers || []).each do |reader|
        if listeners[reader]
          listeners[reader].call(reader)
        else
          if reader.fill.zero?
            reader.close
            stop_listening_to(reader)
          end
        end
      end

      (ready_writers || []).each do |writer|
        writer.send_pending
      end

      transport.rekey_as_needed

      return true
    end

    # Send a global request of the given type. The +extra+ parameters must
    # be even in number, and conform to the same format as described for
    # Net::SSH::Buffer.from. If a callback is not specified, the request will
    # not require a response from the server, otherwise the server is required
    # to respond and indicate whether the request was successful or not. This
    # success or failure is indicated by the callback being invoked, with the
    # first parameter being true or false (success, or failure), and the second
    # being the packet itself.
    def send_global_request(type, *extra, &callback)
      trace { "sending global request #{type}" }
      msg = Buffer.from(:byte, GLOBAL_REQUEST, :string, type.to_s, :bool, !callback.nil?, *extra)
      send_message(msg)
      pending_requests << callback if callback
      self
    end

    # Requests that a new channel be opened. By default, the channel will be
    # of type "session", but if you know what you're doing you can select any
    # of the channel types supported by the SSH protocol. The +extra+ parameters
    # must be even in number and conform to the same format as described for
    # Net::SSH::Buffer.from. If a callback is given, it will be invoked when
    # the server confirms that the channel opened successfully. The sole parameter
    # for the callback is the channel object itself.
    def open_channel(type="session", *extra, &on_confirm)
      local_id = get_next_channel_id
      channel = Channel.new(self, type, local_id, &on_confirm)

      msg = Buffer.from(:byte, CHANNEL_OPEN, :string, type, :long, local_id,
        :long, channel.local_maximum_window_size,
        :long, channel.local_maximum_packet_size, *extra)
      send_message(msg)

      channels[local_id] = channel
    end

    # Enqueues a message to be sent to the server as soon as the socket is
    # available for writing.
    def send_message(message)
      transport.enqueue_message(message)
    end

    # Adds an IO object for the event loop to listen to. If the IO object
    # responds to :pending_write? (e.g. it has been extended with Net::SSH::BufferedIo),
    # it will be added to the list of writers to attend to, as well. If a callback
    # is given, it will be invoked when the io is ready to be read, otherwise,
    # the io will merely have its #fill method invoked.
    def listen_to(io, &callback)
      readers << io
      writers << io if io.respond_to?(:pending_write?)
      listeners[io] = callback if callback
    end

    # Removes the given io object from all applicable lists (readers,
    # writers, listeners), so that the event loop will no longer monitor it.
    def stop_listening_to(io)
      readers.delete(io)
      writers.delete(io)
      listeners.delete(io)
    end

    # Returns a reference to the Service::Forward service, which can be used
    # for forwarding ports over SSH.
    def forward
      @forward ||= Service::Forward.new(self)
    end

    # Registers a handler to be invoked when the server wants to open a
    # channel on the client. The callback receives the connection object,
    # the new channel object, and the packet itself as arguments, and should
    # raise ChannelOpenFailed if it is unable to open the channel for some
    # reason. Otherwise, the channel will be opened and a confirmation message
    # sent to the server.
    def on_open_channel(type, &block)
      channel_open_handlers[type] = block
    end

    # Registers a handler to be invoked when the server sends a global request
    # of the given type. The callback receives the request data as the first
    # parameter, and true/false as the second (indicating whether a response
    # is required). If the callback sends the response, it should return
    # :sent. Otherwise, if it returns true, REQUEST_SUCCESS will be sent, and
    # if it returns false, REQUEST_FAILURE will be sent.
    def on_global_request(type, &block)
      old, @on_global_request[type] = @on_global_request[type], block
      old
    end

    private

      # Read all pending packets from the connection and dispatch them as
      # appropriate. Returns as soon as there are no more pending packets.
      def dispatch_incoming_packets
        while packet = transport.poll_message
          unless MAP.key?(packet.type)
            raise Net::SSH::Exception, "unexpected response #{packet.type} (#{packet.inspect})"
          end

          send(MAP[packet.type], packet)
        end
      end

      # Returns the next available channel id to be assigned, and increments
      # the counter.
      def get_next_channel_id
        @channel_id_counter += 1
      end

      # Invoked when a global request is received. The registered global
      # request callback will be invoked, if one exists, and the necessary
      # reply returned.
      def global_request(packet)
        trace { "global request received: #{packet[:request_type]} #{packet[:want_reply]}" }
        callback = @on_global_request[packet[:request_type]]
        result = callback ? callback.call(packet[:request_data], packet[:want_reply]) : false

        if result != :sent && result != true && result != false
          raise "expected global request handler for `#{packet[:request_type]}' to return true, false, or :sent, but got #{result.inspect}"
        end

        if packet[:want_reply] && result != :sent
          msg = Buffer.from(:byte, result ? REQUEST_SUCCESS : REQUEST_FAILURE)
          send_message(msg)
        end
      end

      # Invokes the next pending request callback with +true+.
      def request_success(packet)
        trace { "global request success" }
        callback = pending_requests.shift
        callback.call(true, packet) if callback
      end

      # Invokes the next pending request callback with +false+.
      def request_failure(packet)
        trace { "global request failure" }
        callback = pending_requests.shift
        callback.call(false, packet) if callback
      end

      # Called when the server wants to open a channel. If no registered
      # channel handler exists for the given channel type, CHANNEL_OPEN_FAILURE
      # is returned, otherwise the callback is invoked and everything proceeds
      # accordingly.
      def channel_open(packet)
        trace { "channel open #{packet[:channel_type]}" }

        local_id = get_next_channel_id
        channel = Channel.new(self, packet[:channel_type], local_id)
        channel.do_open_confirmation(packet[:remote_id], packet[:window_size], packet[:packet_size])

        callback = channel_open_handlers[packet[:channel_type]]

        if callback
          begin
            callback[self, channel, packet]
          rescue ChannelOpenFailed => err
            failure = [err.code, err.reason]
          else
            channels[local_id] = channel
            msg = Buffer.from(:byte, CHANNEL_OPEN_CONFIRMATION, :long, channel.remote_id, :long, channel.local_id, :long, channel.local_maximum_window_size, :long, channel.local_maximum_packet_size)
          end
        else
          failure = [3, "unknown channel type #{channel.type}"]
        end

        if failure
          error { failure.inspect }
          msg = Buffer.from(:byte, CHANNEL_OPEN_FAILURE, :long, channel.remote_id, :long, failure[0], :string, failure[1], :string, "")
        end

        send_message(msg)
      end

      def channel_open_confirmation(packet)
        trace { "channel_open_confirmation: #{packet[:local_id]} #{packet[:remote_id]} #{packet[:window_size]} #{packet[:packet_size]}" }
        channel = channels[packet[:local_id]]
        channel.do_open_confirmation(packet[:remote_id], packet[:window_size], packet[:packet_size])
      end

      def channel_window_adjust(packet)
        trace { "channel_window_adjust: #{packet[:local_id]} +#{packet[:extra_bytes]}" }
        channels[packet[:local_id]].do_window_adjust(packet[:extra_bytes])
      end

      def channel_request(packet)
        trace { "channel_request: #{packet[:local_id]} #{packet[:request]} #{packet[:want_reply]}" }
        channels[packet[:local_id]].do_request(packet[:request], packet[:want_reply], packet[:request_data])
      end

      def channel_data(packet)
        trace { "channel_data: #{packet[:local_id]} #{packet[:data].length}b" }
        channels[packet[:local_id]].do_data(packet[:data])
      end

      def channel_extended_data(packet)
        trace { "channel_extended_data: #{packet[:local_id]} #{packet[:data_type]} #{packet[:data].length}b" }
        channels[packet[:local_id]].do_extended_data(packet[:data_type], packet[:data])
      end

      def channel_eof(packet)
        trace { "channel_eof: #{packet[:local_id]}" }
        channels[packet[:local_id]].do_eof
      end

      def channel_close(packet)
        trace { "channel_close: #{packet[:local_id]}" }

        channel = channels[packet[:local_id]]
        channel.close

        channels.delete(packet[:local_id])
        channel.do_close
      end

      def channel_success(packet)
        trace { "channel_success: #{packet[:local_id]}" }
        channels[packet[:local_id]].do_success
      end

      def channel_failure(packet)
        trace { "channel_failure: #{packet[:local_id]}" }
        channels[packet[:local_id]].do_failure
      end
  end

end; end; end