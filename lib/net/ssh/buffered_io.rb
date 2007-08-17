require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net; module SSH

  # This module is used to extend sockets and other IO objects, to allow
  # them to be buffered for both read and write. This abstraction makes it
  # quite easy to write a select-based event loop (see Connection::Session).
  module BufferedIo
    include Loggable

    # Called when the #extend is called on an object, with this module as the
    # argument. It ensures that the modules instance variables are all properly
    # initialized.
    def self.extended(object) #:nodoc:
      object.__send__(:initialize_buffered_io)
    end

    # Tries to consume up to +n+ bytes of data from the underlying IO object,
    # and adds the data to the input buffer. It returns the number of bytes
    # read.
    def fill(n=8192)
      input.consume!
      data = recv(n)
      trace { "read #{data.length} bytes" }
      input.append(data)
      return data.length
    end

    # Read up to +length+ bytes from the input buffer.
    def read_available(length)
      input.read(length)
    end

    # Returns the number of bytes available to be read from the input buffer,
    # via #read_available.
    def available
      input.available
    end

    # Enqueues data in the output buffer, to be written when #send_pending
    # is called.
    def enqueue(data)
      output.append(data)
    end

    # Returns +true+ if there is data waiting in the output buffer, and
    # +false+ otherwise.
    def pending_write?
      output.length > 0
    end

    # Sends as much of the pending output as possible.
    def send_pending
      if output.length > 0
        sent = send(output.to_s, 0)
        trace { "sent #{sent} bytes" }
        output.consume!(sent)
      end
    end

    # Blocks until the output buffer is empty.
    def wait_for_pending_sends
      send_pending
      while output.length > 0
        result = IO.select(nil, [self]) or next
        next unless result[1].any?
        send_pending
      end
    end

    public # these methods are primarily for use in tests

      def write_buffer #:nodoc:
        output.to_s
      end

      def read_buffer #:nodoc:
        input.to_s
      end

    private

      attr_reader :input, :output, :input_mutex, :output_mutex

      def initialize_buffered_io
        @input = Net::SSH::Buffer.new
        @output = Net::SSH::Buffer.new
      end
  end

end; end