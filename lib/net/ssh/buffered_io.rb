require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net; module SSH

  module BufferedIo
    include Loggable

    def self.extended(object)
      object.__send__(:initialize_buffered_io)
    end

    attr_reader :input, :output

    def fill(n=8192)
      input.consume!
      data = recv(n)
      trace { "read #{data.length} bytes" }
      input.append(data)
      return data.length
    end

    def read_available(length)
      input.read(length)
    end

    def available
      input.available
    end

    def enqueue(data)
      output.append(data)
    end

    def pending_write?
      output.length > 0
    end

    def send_pending
      if pending_write?
        sent = send(output.to_s, 0)
        trace { "sent #{sent} bytes" }
        output.consume!(sent)
      end
    end

    def wait_for_pending_sends
      send_pending
      while pending_write?
        result = IO.select(nil, [self]) or next
        next unless result[1].any?
        send_pending
      end
    end

    private

      def initialize_buffered_io
        @input = Net::SSH::Buffer.new
        @output = Net::SSH::Buffer.new
      end
  end

end; end