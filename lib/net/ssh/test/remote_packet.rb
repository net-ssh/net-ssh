require 'net/ssh/buffer'
require 'net/ssh/test/packet'

module Net; module SSH; module Test

  class RemotePacket < Packet
    def remote?
      true
    end

    def process(packet)
      raise "received packet type #{packet.read_byte} and was not expecting any packet"
    end

    def to_s
      @to_s ||= begin
        instantiate!
        string = Net::SSH::Buffer.from(:byte, @type, *types.zip(@data).flatten).to_s
        [string.length, string].pack("NA*")
      end
    end
  end

end; end; end