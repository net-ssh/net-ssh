require 'zlib'

module Net; module SSH; module Transport

  class State
    attr_reader :socket
    attr_reader :sequence_number
    attr_reader :cipher
    attr_reader :hmac
    attr_reader :compression
    attr_reader :compression_level
    attr_reader :packets
    attr_reader :blocks

    attr_accessor :max_packets
    attr_accessor :max_blocks
    attr_accessor :rekey_limit

    def initialize(socket)
      @socket = socket
      @sequence_number = @packets = @blocks = 0
      @cipher = CipherFactory.get("none")
      @hmac = HMAC.get("none")
      @compression = nil
    end

    def set(values)
      values.each do |key, value|
        instance_variable_set("@#{key}", value)
      end
      reset!
    end

    def increment(packet_length)
      @sequence_number = (@sequence_number + 1) & 0xFFFFFFFF
      @packets += 1
      @blocks += (packet_length + 4) / cipher.block_size
    end

    def compressor
      @compressor ||= Zlib::Deflate.new(compression_level || Zlib::DEFAULT_COMPRESSION)
    end

    def decompressor
      @decompressor ||= Zlib::Inflate.new(nil)
    end

    def compression?
      compression == :standard || (compression == :delayed && socket.hints[:authenticated])
    end

    def compress(data)
      data = data.to_s
      return data unless compression?
      compressor.deflate(data, Zlib::SYNC_FLUSH)
    end

    def decompress(data)
      data = data.to_s
      return data unless compression?
      decompressor.inflate(data)
    end

    def reset!
      @packets = @blocks = 0

      @max_packets ||= 1 << 31

      if max_blocks.nil?
        # cargo-culted from openssh. the idea is that "the 2^(blocksize*2)
        # limit is too expensive for 3DES, blowfish, etc., so enforce a 1GB
        # limit for small blocksizes."

        if cipher.block_size >= 16
          @max_blocks = 1 << (cipher.block_size * 2)
        else
          @max_blocks = (1 << 30) / cipher.block_size
        end

        # if a limit on the # of bytes has been given, convert that into a
        # minimum number of blocks processed.

        if rekey_limit
          @max_blocks = [@max_blocks, rekey_limit / cipher.block_size].min
        end
      end

      cleanup
    end

    def cleanup
      @compressor.close if @compressor
      @decompressor.close if @decompressor
      @compressor = @decompressor = nil
    end

    def needs_rekey?
      max_packets && packets > max_packets ||
      max_blocks && blocks > max_blocks
    end
  end

end; end; end