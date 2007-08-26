require 'net/ssh/test/channel'
require 'net/ssh/test/local_packet'
require 'net/ssh/test/remote_packet'

module Net; module SSH; module Test

  class Script
    attr_reader :events

    def initialize
      @events = []
    end

    def opens_channel(confirm=true)
      channel = Channel.new(self)
      channel.remote_id = 5555

      events << LocalPacket.new(:channel_open) { |p| channel.local_id = p[:remote_id] }

      if confirm
        events << RemotePacket.new(:channel_open_confirmation, channel.local_id, channel.remote_id, 0x20000, 0x10000)
      end

      channel
    end

    def sends(*args)
      events << LocalPacket.new(*args)
    end

    def gets(*args)
      events << RemotePacket.new(*args)
    end

    def sends_channel_request(channel, request, reply, data, success=true)
      events << LocalPacket.new(:channel_request, channel.remote_id, request, reply, data)
      if reply
        if success
          events << RemotePacket.new(:channel_success, channel.local_id)
        else
          events << RemotePacket.new(:channel_failure, channel.local_id)
        end
      end
    end

    def sends_channel_data(channel, data)
      events << LocalPacket.new(:channel_data, channel.remote_id, data)
    end

    def sends_channel_eof(channel)
      events << LocalPacket.new(:channel_eof, channel.remote_id)
    end

    def sends_channel_close(channel)
      events << LocalPacket.new(:channel_close, channel.remote_id)
    end

    def gets_channel_data(channel, data)
      events << RemotePacket.new(:channel_data, channel.local_id, data)
    end

    def gets_channel_request(channel, request, reply, data)
      events << RemotePacket.new(:channel_request, channel.local_id, request, reply, data)
    end

    def gets_channel_eof(channel)
      events << RemotePacket.new(:channel_eof, channel.local_id)
    end

    def gets_channel_close(channel)
      events << RemotePacket.new(:channel_close, channel.local_id)
    end

    def next(mode=:shift)
      events.send(mode)
    end

    def process(packet)
      event = events.shift or raise "end of script reached, but got a packet type #{packet.read_byte}"
      event.process(packet)
    end
  end

end; end; end