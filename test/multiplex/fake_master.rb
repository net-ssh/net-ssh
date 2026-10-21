require 'socket'
require 'tmpdir'
require 'net/ssh/buffer'
require 'net/ssh/connection/constants'

# A stand-in for an OpenSSH ControlMaster listening on a UNIX socket: it
# speaks the mux HELLO/PROXY handshake and then answers session channels the
# way a server would, recording the connection-protocol messages it receives.
class FakeMaster
  include Net::SSH::Connection::Constants

  attr_reader :path, :received, :connections

  # +mode+ is :proxy, :old_version, :refuse or :silent.
  def initialize(path, mode: :proxy, output: "hello\n", exit_status: 0)
    @path = path
    @mode = mode
    @output = output
    @exit_status = exit_status
    @received = Queue.new
    @connections = 0
    @server = UNIXServer.new(path)
    @thread = Thread.new { serve }
    @thread.report_on_exception = false
  end

  def received_types
    drain_received.map(&:first)
  end

  def received_requests
    drain_received.filter_map { |type, request| request if type == CHANNEL_REQUEST }
  end

  def drain_received
    packets = []
    packets << @received.pop until @received.empty?
    packets
  end

  def stop
    @thread.kill
    @thread.join
    @server.close unless @server.closed?
    @client&.close unless @client.nil? || @client.closed?
  end

  private

  def serve
    loop do
      @client = @server.accept
      @connections += 1
      handle(@client)
    rescue StandardError
      next
    end
  end

  def handle(client)
    return sleep if @mode == :silent

    write_mux(client, Net::SSH::Buffer.from(:long, 1, :long, @mode == :old_version ? 3 : 4, :string, "info", :string, "0"))
    read_mux(client)
    request = read_mux(client)
    request.read_long
    request_id = request.read_long
    if @mode == :refuse
      write_mux(client, Net::SSH::Buffer.from(:long, 0x80000002, :long, request_id, :string, "Permission denied"))
      return
    end

    write_mux(client, Net::SSH::Buffer.from(:long, 0x8000000f, :long, request_id))
    loop { answer(client, read_packet(client)) }
  end

  def answer(client, packet)
    type = packet.read_byte
    case type
    when CHANNEL_OPEN
      packet.read_string
      id = packet.read_long
      @received << [type, nil]
      send_packet(client, :byte, CHANNEL_OPEN_CONFIRMATION, :long, id, :long, id + 100, :long, 0x200000, :long, 0x8000)
      @channel = id
      @closed = false
    when CHANNEL_REQUEST
      packet.read_long
      request = packet.read_string
      want_reply = packet.read_bool
      @received << [type, request]
      send_packet(client, :byte, CHANNEL_SUCCESS, :long, @channel) if want_reply
      return unless request == "exec"

      send_packet(client, :byte, CHANNEL_DATA, :long, @channel, :string, @output)
      send_packet(client, :byte, CHANNEL_REQUEST, :long, @channel, :string, "exit-status", :bool, false, :long, @exit_status)
      send_packet(client, :byte, CHANNEL_EOF, :long, @channel)
      send_packet(client, :byte, CHANNEL_CLOSE, :long, @channel)
      @closed = true
    when CHANNEL_CLOSE
      @received << [type, nil]
      send_packet(client, :byte, CHANNEL_CLOSE, :long, @channel) unless @closed
    else
      @received << [type, nil]
    end
  end

  def write_mux(client, buffer)
    data = buffer.to_s
    client.write([data.bytesize].pack('N') + data)
  end

  def read_mux(client)
    Net::SSH::Buffer.new(client.read(client.read(4).unpack1('N')))
  end

  def read_packet(client)
    data = client.read(4) or raise EOFError
    data = client.read(data.unpack1('N'))
    raise "unexpected padding" unless data.getbyte(0) == 0

    Net::SSH::Buffer.new(data.byteslice(1..-1))
  end

  def send_packet(client, *args)
    payload = Net::SSH::Buffer.from(*args).to_s
    client.write([payload.bytesize + 1, 0].pack('NC') + payload)
  end
end
