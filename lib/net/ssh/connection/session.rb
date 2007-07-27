require 'net/ssh/loggable'
require 'net/ssh/connection/channel'
require 'net/ssh/connection/constants'

module Net; module SSH; module Connection

  class Session
    include Constants, Loggable

    MAP = Constants.constants.inject({}) do |memo, name|
      memo[const_get(name)] = name.downcase.to_sym
      memo
    end

    attr_reader :transport
    attr_reader :channels
    attr_reader :listeners
    attr_reader :pending_requests
    attr_reader :readers
    attr_reader :writers
    attr_reader :channel_open_handler

    def initialize(transport, options={})
      self.logger = transport.logger

      @transport = transport

      @channel_id_counter = -1
      @channels = {}
      @listeners = {}
      @pending_requests = []
      @readers = [transport.socket]
      @writers = [transport.socket]
      @channel_open_handler = {}
    end

    def close
      channels.each { |id, channel| channel.close }
      loop { channels.any? }
      transport.close
    end

    # preserve a reference to Kernel#loop
    alias :loop_forever :loop

    def loop(&block)
      running = block || Proc.new { channels.any? { |id,ch| ch.important? } }
      process while running.call
    end

    def process(wait=nil)
      dispatch_incoming_packets
      channels.each { |id, channel| channel.process unless channel.closing? }

      w = writers.select { |w| w.pending_write? }
      ready_readers, ready_writers, errors = IO.select(readers, w, nil, wait)

      (ready_readers || []).each do |reader|
        if listeners[reader]
          listeners[reader].call(reader)
        else
          if reader.fill.zero?
            reader.close
            readers.delete(reader)
            writers.delete(reader) # just in case it was a writer, too
          end
        end
      end

      (ready_writers || []).each do |writer|
        writer.send_pending
      end
    end

    def global_request(type, *extra, &callback)
      trace { "sending global request #{type}" }
      msg = Buffer.from(:byte, GLOBAL_REQUEST, :string, type.to_s, :bool, !callback.nil?, *extra)
      send_message(msg)
      pending_requests << callback if callback
      self
    end

    def open_channel(type, *extra, &on_confirm)
      local_id = get_next_channel_id
      channel = Channel.new(self, type, local_id, &on_confirm)

      msg = Buffer.from(:byte, CHANNEL_OPEN, :string, type, :long, local_id,
        :long, channel.local_maximum_window_size,
        :long, channel.local_maximum_packet_size, *extra)
      send_message(msg)

      channels[local_id] = channel
    end

    def send_message(message)
      transport.socket.enqueue_packet(message)
    end

    def listen_to(io, &callback)
      readers << io
      @listeners[io] = callback
    end

    def on_open_channel(type, &block)
      channel_open_handler[type] = block
    end

    private

      def dispatch_incoming_packets
        while packet = transport.poll_message
          unless MAP.key?(packet.type)
            raise Net::SSH::Exception, "unexpected response #{packet.type} (#{packet.inspect})"
          end

          send(MAP[packet.type], packet)
        end
      end

      def get_next_channel_id
        @channel_id_counter += 1
      end

      def request_success(packet)
        trace { "global request success" }
        callback = pending_requests.shift
        callback.call(true, packet) if callback
      end

      def request_failure(packet)
        trace { "global request failure" }
        callback = pending_requests.shift
        callback.call(false, packet) if callback
      end

      def channel_open(packet)
        trace { "channel open #{packet[:channel_type]}" }

        local_id = get_next_channel_id
        channel = Channel.new(self, packet[:channel_type], local_id)
        channel.do_open_confirmation(packet[:remote_id], packet[:window_size], packet[:packet_size])

        callback = channel_open_handler[packet[:channel_type]]

        if callback
          result = callback[self, channel, packet]
          if Array === result && result.length == 2
            failure = result
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
        channels[packet[:local_id]].do_open_confirmation(packet[:remote_id], packet[:window_size], packet[:packet_size])
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
  end

end; end; end