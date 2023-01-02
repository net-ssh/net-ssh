require 'net/ssh/transport/openssl'

require 'net/ssh/authentication/certificate'
require 'net/ssh/authentication/ed25519_loader'

module Net
  module SSH
    # Net::SSH::Buffer is a flexible class for building and parsing binary
    # data packets. It provides a stream-like interface for sequentially
    # reading data items from the buffer, as well as a useful helper method
    # for building binary packets given a signature.
    #
    # Writing to a buffer always appends to the end, regardless of where the
    # read cursor is. Reading, on the other hand, always begins at the first
    # byte of the buffer and increments the read cursor, with subsequent reads
    # taking up where the last left off.
    #
    # As a consumer of the Net::SSH library, you will rarely come into contact
    # with these buffer objects directly, but it could happen. Also, if you
    # are ever implementing a protocol on top of SSH (e.g. SFTP), this buffer
    # class can be quite handy.
    class Buffer
      # This is a convenience method for creating and populating a new buffer
      # from a single command. The arguments must be even in length, with the
      # first of each pair of arguments being a symbol naming the type of the
      # data that follows. If the type is :raw, the value is written directly
      # to the hash.
      #
      #   b = Buffer.from(:byte, 1, :string, "hello", :raw, "\1\2\3\4")
      #   #-> "\1\0\0\0\5hello\1\2\3\4"
      #
      # The supported data types are:
      #
      # * :raw => write the next value verbatim (#write)
      # * :int64 => write an 8-byte integer (#write_int64)
      # * :long => write a 4-byte integer (#write_long)
      # * :byte => write a single byte (#write_byte)
      # * :string => write a 4-byte length followed by character data (#write_string)
      # * :mstring => same as string, but caller cannot resuse the string, avoids potential duplication (#write_moved)
      # * :bool => write a single byte, interpreted as a boolean (#write_bool)
      # * :bignum => write an SSH-encoded bignum (#write_bignum)
      # * :key => write an SSH-encoded key value (#write_key)
      #
      # Any of these, except for :raw, accepts an Array argument, to make it
      # easier to write multiple values of the same type in a briefer manner.
      def self.from(*args)
        raise ArgumentError, "odd number of arguments given" unless args.length % 2 == 0

        buffer = new
        0.step(args.length - 1, 2) do |index|
          type = args[index]
          value = args[index + 1]
          if type == :raw
            buffer.append(value.to_s)
          elsif Array === value
            buffer.send("write_#{type}", *value)
          else
            buffer.send("write_#{type}", value)
          end
        end

        buffer
      end

      # exposes the raw content of the buffer
      attr_reader :content

      # the current position of the pointer in the buffer
      attr_accessor :position

      # Creates a new buffer, initialized to the given content. The position
      # is initialized to the beginning of the buffer.
      def initialize(content = String.new)
        @content = content.to_s
        @position = 0
      end

      # Returns the length of the buffer's content.
      def length
        @content.length
      end

      # Returns the number of bytes available to be read (e.g., how many bytes
      # remain between the current position and the end of the buffer).
      def available
        length - position
      end

      # Returns a copy of the buffer's content.
      def to_s
        (@content || "").dup
      end

      # Compares the contents of the two buffers, returning +true+ only if they
      # are identical in size and content.
      def ==(buffer)
        to_s == buffer.to_s
      end

      # Returns +true+ if the buffer contains no data (e.g., it is of zero length).
      def empty?
        @content.empty?
      end

      # Resets the pointer to the start of the buffer. Subsequent reads will
      # begin at position 0.
      def reset!
        @position = 0
      end

      # Returns true if the pointer is at the end of the buffer. Subsequent
      # reads will return nil, in this case.
      def eof?
        @position >= length
      end

      # Resets the buffer, making it empty. Also, resets the read position to
      # 0.
      def clear!
        @content = String.new
        @position = 0
      end

      # Consumes n bytes from the buffer, where n is the current position
      # unless otherwise specified. This is useful for removing data from the
      # buffer that has previously been read, when you are expecting more data
      # to be appended. It helps to keep the size of buffers down when they
      # would otherwise tend to grow without bound.
      #
      # Returns the buffer object itself.
      def consume!(n = position)
        if n >= length
          # optimize for a fairly common case
          clear!
        elsif n > 0
          @content = @content[n..-1] || String.new
          @position -= n
          @position = 0 if @position < 0
        end
        self
      end

      # Appends the given text to the end of the buffer. Does not alter the
      # read position. Returns the buffer object itself.
      def append(text)
        @content << text
        self
      end

      # Returns all text from the current pointer to the end of the buffer as
      # a new Net::SSH::Buffer object.
      def remainder_as_buffer
        Buffer.new(@content[@position..-1])
      end

      # Reads all data up to and including the given pattern, which may be a
      # String, Fixnum, or Regexp and is interpreted exactly as String#index
      # does. Returns nil if nothing matches. Increments the position to point
      # immediately after the pattern, if it does match. Returns all data up to
      # and including the text that matched the pattern.
      def read_to(pattern)
        index = @content.index(pattern, @position) or return nil
        length = case pattern
                 when String then pattern.length
                 when Integer then 1
                 when Regexp then $&.length
                 end
        index && read(index + length)
      end

      # Reads and returns the next +count+ bytes from the buffer, starting from
      # the read position. If +count+ is +nil+, this will return all remaining
      # text in the buffer. This method will increment the pointer.
      def read(count = nil)
        count ||= length
        count = length - @position if @position + count > length
        @position += count
        @content[@position - count, count]
      end

      # Reads (as #read) and returns the given number of bytes from the buffer,
      # and then consumes (as #consume!) all data up to the new read position.
      def read!(count = nil)
        data = read(count)
        consume!
        data
      end

      # Calls block(self) until the buffer is empty, and returns all results.
      def read_all(&block)
        Enumerator.new { |e| e << yield(self) until eof? }.to_a
      end

      # Return the next 8 bytes as a 64-bit integer (in network byte order).
      # Returns nil if there are less than 8 bytes remaining to be read in the
      # buffer.
      def read_int64
        hi = read_long or return nil
        lo = read_long or return nil
        return (hi << 32) + lo
      end

      # Return the next four bytes as a long integer (in network byte order).
      # Returns nil if there are less than 4 bytes remaining to be read in the
      # buffer.
      def read_long
        b = read(4) or return nil
        b.unpack("N").first
      end

      # Read and return the next byte in the buffer. Returns nil if called at
      # the end of the buffer.
      def read_byte
        b = read(1) or return nil
        b.getbyte(0)
      end

      # Read and return an SSH2-encoded string. The string starts with a long
      # integer that describes the number of bytes remaining in the string.
      # Returns nil if there are not enough bytes to satisfy the request.
      def read_string
        length = read_long or return nil
        read(length)
      end

      # Read a single byte and convert it into a boolean, using 'C' rules
      # (i.e., zero is false, non-zero is true).
      def read_bool
        b = read_byte or return nil
        b != 0
      end

      # Read a bignum (OpenSSL::BN) from the buffer, in SSH2 format. It is
      # essentially just a string, which is reinterpreted to be a bignum in
      # binary format.
      def read_bignum
        data = read_string
        return unless data

        OpenSSL::BN.new(data, 2)
      end

      # Read a key from the buffer. The key will start with a string
      # describing its type. The remainder of the key is defined by the
      # type that was read.
      def read_key
        type = read_string
        return (type ? read_keyblob(type) : nil)
      end

      def read_private_keyblob(type)
        case type
        when /^ssh-rsa$/
          n = read_bignum
          e = read_bignum
          d = read_bignum
          iqmp = read_bignum
          p = read_bignum
          q = read_bignum
          _unkown1 = read_bignum
          _unkown2 = read_bignum
          dmp1 = d % (p - 1)
          dmq1 = d % (q - 1)
          # Public key
          data_sequence = OpenSSL::ASN1::Sequence([
                                                    OpenSSL::ASN1::Integer(n),
                                                    OpenSSL::ASN1::Integer(e)
                                                  ])

          if d && p && q && dmp1 && dmq1 && iqmp
            data_sequence = OpenSSL::ASN1::Sequence([
                                                      OpenSSL::ASN1::Integer(0),
                                                      OpenSSL::ASN1::Integer(n),
                                                      OpenSSL::ASN1::Integer(e),
                                                      OpenSSL::ASN1::Integer(d),
                                                      OpenSSL::ASN1::Integer(p),
                                                      OpenSSL::ASN1::Integer(q),
                                                      OpenSSL::ASN1::Integer(dmp1),
                                                      OpenSSL::ASN1::Integer(dmq1),
                                                      OpenSSL::ASN1::Integer(iqmp)
                                                    ])
          end

          asn1 = OpenSSL::ASN1::Sequence(data_sequence)
          OpenSSL::PKey::RSA.new(asn1.to_der)
        when /^ecdsa\-sha2\-(\w*)$/
          OpenSSL::PKey::EC.read_keyblob($1, self)
        else
          raise Exception, "Cannot decode private key of type #{type}"
        end
      end

      # Read a keyblob of the given type from the buffer, and return it as
      # a key. Only RSA, DSA, and ECDSA keys are supported.
      def read_keyblob(type)
        case type
        when /^(.*)-cert-v01@openssh\.com$/
          key = Net::SSH::Authentication::Certificate.read_certblob(self, $1)
        when /^ssh-dss$/
          p = read_bignum
          q = read_bignum
          g = read_bignum
          pub_key = read_bignum

          asn1 = OpenSSL::ASN1::Sequence.new(
            [
              OpenSSL::ASN1::Sequence.new(
                [
                  OpenSSL::ASN1::ObjectId.new('DSA'),
                  OpenSSL::ASN1::Sequence.new(
                    [
                      OpenSSL::ASN1::Integer.new(p),
                      OpenSSL::ASN1::Integer.new(q),
                      OpenSSL::ASN1::Integer.new(g)
                    ]
                  )
                ]
              ),
              OpenSSL::ASN1::BitString.new(OpenSSL::ASN1::Integer.new(pub_key).to_der)
            ]
          )

          key = OpenSSL::PKey::DSA.new(asn1.to_der)
        when /^ssh-rsa$/
          e = read_bignum
          n = read_bignum

          asn1 = OpenSSL::ASN1::Sequence(
            [
              OpenSSL::ASN1::Integer(n),
              OpenSSL::ASN1::Integer(e)
            ]
          )

          key = OpenSSL::PKey::RSA.new(asn1.to_der)
        when /^ssh-ed25519$/
          Net::SSH::Authentication::ED25519Loader.raiseUnlessLoaded("unsupported key type `#{type}'")
          key = Net::SSH::Authentication::ED25519::PubKey.read_keyblob(self)
        when /^ecdsa\-sha2\-(\w*)$/
          key = OpenSSL::PKey::EC.read_keyblob($1, self)
        else
          raise NotImplementedError, "unsupported key type `#{type}'"
        end

        return key
      end

      # Reads the next string from the buffer, and returns a new Buffer
      # object that wraps it.
      def read_buffer
        Buffer.new(read_string)
      end

      # Writes the given data literally into the string. Does not alter the
      # read position. Returns the buffer object.
      def write(*data)
        data.each { |datum| @content << datum.dup.force_encoding('BINARY') }
        self
      end

      # Optimized version of write where the caller gives up ownership of string
      # to the method. This way we can mutate the string.
      def write_moved(string)
        @content <<
          if string.frozen?
            string.dup.force_encoding('BINARY')
          else
            string.force_encoding('BINARY')
          end
        self
      end

      # Writes each argument to the buffer as a network-byte-order-encoded
      # 64-bit integer (8 bytes). Does not alter the read position. Returns the
      # buffer object.
      def write_int64(*n)
        n.each do |i|
          hi = (i >> 32) & 0xFFFFFFFF
          lo = i & 0xFFFFFFFF
          @content << [hi, lo].pack("N2")
        end
        self
      end

      # Writes each argument to the buffer as a network-byte-order-encoded
      # long (4-byte) integer. Does not alter the read position. Returns the
      # buffer object.
      def write_long(*n)
        @content << n.pack("N*")
        self
      end

      # Writes each argument to the buffer as a byte. Does not alter the read
      # position. Returns the buffer object.
      def write_byte(*n)
        n.each { |b| @content << b.chr }
        self
      end

      # Writes each argument to the buffer as an SSH2-encoded string. Each
      # string is prefixed by its length, encoded as a 4-byte long integer.
      # Does not alter the read position. Returns the buffer object.
      def write_string(*text)
        text.each do |string|
          s = string.to_s
          write_long(s.bytesize)
          write(s)
        end
        self
      end

      # Writes each argument to the buffer as an SSH2-encoded string. Each
      # string is prefixed by its length, encoded as a 4-byte long integer.
      # Does not alter the read position. Returns the buffer object.
      # Might alter arguments see write_moved
      def write_mstring(*text)
        text.each do |string|
          s = string.to_s
          write_long(s.bytesize)
          write_moved(s)
        end
        self
      end

      # Writes each argument to the buffer as a (C-style) boolean, with 1
      # meaning true, and 0 meaning false. Does not alter the read position.
      # Returns the buffer object.
      def write_bool(*b)
        b.each { |v| @content << (v ? "\1" : "\0") }
        self
      end

      # Writes each argument to the buffer as a bignum (SSH2-style). No
      # checking is done to ensure that the arguments are, in fact, bignums.
      # Does not alter the read position. Returns the buffer object.
      def write_bignum(*n)
        @content << n.map { |b| b.to_ssh }.join
        self
      end

      # Writes the given arguments to the buffer as SSH2-encoded keys. Does not
      # alter the read position. Returns the buffer object.
      def write_key(*key)
        key.each { |k| append(k.to_blob) }
        self
      end
    end
  end
end;
