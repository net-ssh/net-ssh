require 'net/ssh/packet'
require 'net/ssh/test/packet'

module Net; module SSH; module Test

  class LocalPacket < Packet
    def local?
      true
    end

    def process(packet)
      @init.call(Net::SSH::Packet.new(packet.to_s)) if @init
      type = packet.read_byte
      raise "expected #{@type}, but got #{type}" if @type != type

      @data.zip(types).each do |expected, type|
        type ||= case expected
          when nil then break
          when Numeric then :long
          when String then :string
          when TrueClass, FalseClass then :bool
          end

        actual = packet.send(:"read_#{type}")
        next if expected.nil?
        raise "expected #{type} `#{expected}' but got `#{actual}'" unless expected == actual
      end
    end
  end

end; end; end