require 'thread'
require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net; module SSH

  module BufferedIo
    include Loggable

    def self.extended(object)
      object.__send__(:initialize_buffered_io)
    end

    def fill(n=8192)
      input_mutex.synchronize do
        input.consume!
        data = recv(n)
        trace { "read #{data.length} bytes" }
        input.append(data)
        return data.length
      end
    end

    def read_available(length)
      input_mutex.synchronize { input.read(length) }
    end

    def available
      input_mutex.synchronize { input.available }
    end

    def enqueue(data)
      output_mutex.synchronize { output.append(data) }
    end

    def pending_write?
      output_mutex.synchronize { output.length > 0 }
    end

    def send_pending
      output_mutex.synchronize do
        if output.length > 0
          sent = send(output.to_s, 0)
          trace { "sent #{sent} bytes" }
          output.consume!(sent)
        end
      end
    end

    def wait_for_pending_sends
      send_pending
      while output.length > 0
        result = IO.select(nil, [self]) or next
        next unless result[1].any?
        send_pending
      end
    end

    private

      attr_reader :input, :output, :input_mutex, :output_mutex

      def initialize_buffered_io
        @input = Net::SSH::Buffer.new
        @output = Net::SSH::Buffer.new
        @input_mutex = Mutex.new
        @output_mutex = Mutex.new
      end
  end

end; end