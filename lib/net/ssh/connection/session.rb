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

    def initialize(transport, options={})
      self.logger = transport.logger

      @transport = transport

      @next_channel_id = 0
      @channels = {}
    end

    # preserve a reference to Kernel#loop
    alias :loop_forever :loop

    def loop(&block)
      running = block || Proc.new { channels.any? { |id,ch| ch.important? } }

      while running.call
        process
      end
    end

    def process
      dispatch_incoming_packets

      channels.each { |id, channel| channel.enqueue_pending_output }

      readers = [transport.socket]
      writers = []
      writers << transport.socket if transport.socket.pending_write?

      readers, writers, errors = IO.select(readers, writers, nil, 0)

      if readers
        transport.socket.fill if readers.include?(transport.socket)
      end

      if writers
        transport.socket.send_queue if writers.include?(transport.socket)
      end
    end

    def open_channel(type, &on_confirm)
      local_id = @next_channel_id += 1
      channel = Channel.new(self, type, local_id, &on_confirm)

      msg = Buffer.from(:byte, CHANNEL_OPEN, :string, type, :long, local_id,
        :long, channel.local_maximum_window_size,
        :long, channel.local_maximum_packet_size)
      send_message(msg)

      channels[local_id] = channel
    end

    def send_message(message)
      transport.socket.enqueue_packet(message)
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
        send_message(Buffer.from(:byte, CHANNEL_CLOSE, :long, channel.remote_id))

        channels.delete(packet[:local_id])
        channel.do_close
      end
  end

end; end; end