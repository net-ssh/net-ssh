require 'net/ssh/buffer'
require 'net/ssh/packet'
require 'net/ssh/buffered_io'
require 'net/ssh/connection/channel'
require 'net/ssh/connection/constants'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/packet_stream'

module Net::SSH::BufferedIo
  def select_for_read?
    pos < size
  end

  attr_accessor :select_for_write, :select_for_error
  alias select_for_write? select_for_write
  alias select_for_error? select_for_error
end


module Net::SSH::Transport::PacketStream
  include Net::SSH::Connection::Constants
  include Net::SSH::Transport::Constants

  MAP = Hash.new { |h,k| const_get(k.to_s.upcase) }

  def idle!
    return false unless script.next(:first)

    if script.next(:first).remote?
      self.string << script.next.to_s
      self.pos = pos
    end

    return true
  end

  alias real_available_for_read? available_for_read?
  def available_for_read?
    return true if select_for_read?
    idle!
    false
  end

  alias real_enqueue_packet enqueue_packet
  def enqueue_packet(payload)
    packet = Net::SSH::Buffer.new(payload.to_s)
    script.process(packet)
  end

  alias real_poll_next_packet poll_next_packet
  def poll_next_packet
    return nil if available <= 0
    packet = Net::SSH::Buffer.new(read_available(4))
    length = packet.read_long
    Net::SSH::Packet.new(read_available(length))
  end
end

class Net::SSH::Connection::Channel
  alias original_send_data send_data
  def send_data(data)
    original_send_data(data)
    # force each packet of sent data to be enqueued separately, so that
    # scripted sends are properly interpreted.
    enqueue_pending_output
  end
end

class IO
  class <<self
    alias real_select select
    def select(readers=nil, writers=nil, errors=nil, wait=nil)
      ready_readers = Array(readers).select { |r| r.select_for_read? }
      ready_writers = Array(writers).select { |r| r.select_for_write? }
      ready_errors  = Array(errors).select  { |r| r.select_for_error? }

      if ready_readers.any? || ready_writers.any? || ready_errors.any?
        return [ready_readers, ready_writers, ready_errors]
      end

      processed = 0
      Array(readers).each do |reader|
        processed += 1 if reader.idle!
      end

      raise "no readers were ready for reading, and none had any incoming packets" if processed == 0
    end
  end
end