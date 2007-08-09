require 'net/ssh/buffered_io'
require 'net/ssh/packet'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/transport/hmac'

module Net; module SSH; module Transport

  module PacketStream
    include BufferedIo

    def self.extended(object)
      object.__send__(:initialize_ssh)
    end

    attr_reader :server_sequence_number
    attr_reader :client_sequence_number

    attr_accessor :server_cipher
    attr_accessor :client_cipher

    attr_accessor :server_hmac
    attr_accessor :client_hmac

    def client_name
      @client_name ||= begin
        sockaddr = getsockname
        begin
          Socket.getnameinfo(sockaddr, Socket::NI_NAMEREQD).first
        rescue
          begin
            Socket.getnameinfo(sockaddr).first
          rescue
            begin
              Socket.gethostbyname(Socket.gethostname).first
            rescue
              error { "the client ipaddr/name could not be determined" }
              "unknown"
            end
          end
        end
      end
    end

    def available_for_read?
      result = IO.select([self], nil, nil, 0)
      result && result.first.any?
    end

    def next_packet(mode=:nonblock)
      case mode
      when :nonblock then
        fill if available_for_read?
        poll_next_packet

      when :block then
        loop do
          packet = poll_next_packet
          return packet if packet

          loop do
            result = IO.select([self]) or next
            break if result.first.any?
          end

          if fill <= 0
            raise Net::SSH::Disconnect, "connection closed by remote host"
          end
        end

      else
        raise ArgumentError, "expected :block or :nonblock, got #{mode.inspect}"
      end
    end

    def send_packet(payload)
      enqueue_packet(payload)
      wait_for_pending_sends
    end

    def enqueue_packet(payload)
      payload = payload.to_s

      # the length of the packet, minus the padding
      actual_length = 4 + payload.length + 1

      # compute the padding length
      padding_length = client_cipher.block_size - (actual_length % client_cipher.block_size)
      padding_length += client_cipher.block_size if padding_length < 4

      # compute the packet length (sans the length field itself)
      packet_length = payload.length + padding_length + 1

      if packet_length < 16
        padding_length += client_cipher.block_size
        packet_length = payload.length + padding_length + 1
      end

      padding = Array.new(padding_length) { rand(256) }.pack("C*")

      unencrypted_data = [packet_length, padding_length, payload, padding].pack("NCA*A*")
      mac = client_hmac.digest([client_sequence_number, unencrypted_data].pack("NA*"))

      encrypted_data = client_cipher.update(unencrypted_data) << client_cipher.final
      message = encrypted_data + mac

      trace { "queueing packet nr #{@client_sequence_number} type #{payload[0]} len #{packet_length}" }
      enqueue(message)

      @client_sequence_number += 1
      @client_sequence_number = 0 if @client_sequence_number > 0xFFFFFFFF

      self
    end

    protected
    
      def initialize_ssh
        @server_sequence_number = @client_sequence_number = 0
        @server_cipher = @client_cipher = CipherFactory.get("none")
        @server_hmac = @client_hmac = HMAC.get("none")
        initialize_buffered_io
      end

      def poll_next_packet
        if @packet.nil?
          minimum = server_cipher.block_size < 4 ? 4 : server_cipher.block_size
          return nil if available < minimum
          data = read_available(minimum)

          # decipher it
          @packet = Net::SSH::Buffer.new(server_cipher.update(data))
          @packet_length = @packet.read_long
        end

        need = @packet_length + 4 - server_cipher.block_size
        raise Net::SSH::Exception, "padding error, need #{need} block #{server_cipher.block_size}" if need % server_cipher.block_size != 0

        return nil if available < need + server_hmac.mac_length

        if need > 0
          # read the remainder of the packet and decrypt it.
          data = read_available(need)
          @packet.append(server_cipher.update(data))
        end

        # get the hmac from the tail of the packet (if one exists), and
        # then validate it.
        real_hmac = read_available(server_hmac.mac_length) || ""

        @packet.append(server_cipher.final)
        padding_length = @packet.read_byte

        payload = @packet.read(@packet_length - padding_length - 1)
        padding = @packet.read(padding_length) if padding_length > 0

        my_computed_hmac = server_hmac.digest([server_sequence_number, @packet.content].pack("NA*"))
        raise Net::SSH::Exception, "corrupted mac detected" if real_hmac != my_computed_hmac

        trace { "received packet nr #{@server_sequence_number} type #{payload[0]} len #{@packet_length}" }

        @server_sequence_number += 1
        @server_sequence_number = 0 if @server_sequence_number > 0xFFFFFFFF

        @packet = nil

        return Packet.new(payload)
      end
  end

end; end; end