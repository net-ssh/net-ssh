require_relative '../common'
require 'net/ssh/authentication/agent'
require 'io/wait'
require 'timeout'
require 'net/ssh/connection/channel'
require 'net/ssh/connection/session'
require 'net/ssh/service/forward'

module Service
  class TestForward < NetSSHTest
    include Net::SSH::Connection::Constants

    def test_auth_agent_channel_should_connect_to_identity_agent
      session = stub("session", logger: nil, options: { forward_agent: true, identity_agent: "/tmp/agent.sock" }, on_open_channel: nil)
      forward = Net::SSH::Service::Forward.new(session)
      agent_socket = stub("agent_socket")

      Net::SSH::Authentication::Agent.expects(:connect).with(nil, nil, "/tmp/agent.sock").returns(stub("agent", socket: agent_socket))
      forward.expects(:prepare_simple_client).with(agent_socket, anything, :agent)

      forward.send(:auth_agent_channel, session, {}, nil)
    end

    def test_forwarded_channel_should_pause_reading_while_remote_window_is_full
      channel = prepared_channel(remote_window: 10)

      @peer.write("x" * 20)
      @client.fill
      channel.process
      assert_equal 10, channel.output.length
      assert @session.reading_paused?(@client)

      channel.do_data("reply")
      @client.send_pending
      assert_equal "reply", @peer.read_nonblock(100)

      channel.do_window_adjust(100)
      channel.process
      assert_equal 0, channel.output.length
      assert !@session.reading_paused?(@client)
    end

    def test_forwarded_channel_should_grant_window_only_for_bytes_written_to_the_socket
      channel = prepared_channel(remote_window: 10)

      received = +""
      # Ruby 2.7 sockets block in send until everything is written, so keep reading.
      reader = Thread.new do
        loop { received << @peer.readpartial(0x20000) }
      rescue IOError
        nil
      end
      channel.do_data("x" * 0x10001)
      assert_empty @session.sent

      @client.send_pending
      written = 0x10001 - @client.write_buffer.length
      Timeout.timeout(5) { Thread.pass until received.length == written }
      reader.kill
      adjust = @session.sent.last
      assert_equal CHANNEL_WINDOW_ADJUST, adjust.read_byte
      adjust.read_long
      assert_equal written + 0x20000, adjust.read_long
    end

    def test_forwarded_channel_should_close_when_paused_peer_disconnects_and_data_keeps_arriving
      channel = prepared_channel(remote_window: 10)
      @peer.write("x" * 20)
      @client.fill
      channel.process
      assert @session.reading_paused?(@client)

      @peer.close
      @peer = nil
      channel.do_data("a" * 100)
      assert_nothing_raised { @client.send_pending }
      assert !@client.pending_write?
      channel.do_data("b" * 100)
      assert_nothing_raised { @client.send_pending }

      assert @client.closed?
      channel.process
      assert !@session.listening?(@client)
      assert channel.closing?
    end

    def test_forwarded_channel_should_not_leak_window_on_extended_data
      channel = prepared_channel(remote_window: 10)

      3.times { channel.do_extended_data(1, "e" * 0x10001) }
      assert_operator channel.local_window_size, :>=, channel.local_maximum_window_size / 2
    end

    def test_forwarded_channel_should_deliver_pending_data_before_shutting_down_on_eof
      channel = prepared_channel(remote_window: 10)
      data = "z" * (1024 * 1024)

      reader = Thread.new do
        sleep 0.2
        @peer.read
      end
      channel.do_data(data)
      @client.send_pending
      channel.do_eof
      @client.send_pending while @client.pending_write? && @client.wait_writable(5)

      assert_equal data.length, reader.value.length
    end

    def test_forwarded_channel_should_deliver_data_that_arrives_with_eof_and_close
      data = "z" * (256 * 1024)
      channel = channel_in_session
      @transport.return(CHANNEL_DATA, :long, channel.local_id, :string, data)
      @transport.return(CHANNEL_EOF, :long, channel.local_id)
      @transport.return(CHANNEL_CLOSE, :long, channel.local_id)

      reader = Thread.new do
        sleep 0.2
        @peer.read
      end
      Timeout.timeout(5) { @ssh.loop(0.1) }

      assert_equal data.length, reader.value.length
      assert @client.closed?
      assert !@ssh.listeners.key?(@client)
    end

    def test_forwarded_channel_should_deliver_pending_data_on_remote_close
      data = "y" * (256 * 1024)
      channel = channel_in_session
      @transport.return(CHANNEL_DATA, :long, channel.local_id, :string, data)
      @transport.return(CHANNEL_CLOSE, :long, channel.local_id)

      reader = Thread.new do
        sleep 0.2
        @peer.read
      end
      Timeout.timeout(5) { @ssh.loop(0.1) }

      assert_equal data.length, reader.value.length
      assert !@ssh.listeners.key?(@client)
    end

    def test_forwarded_channel_should_stop_draining_when_the_local_peer_goes_away
      channel = channel_in_session
      @peer.close
      @peer = nil
      @transport.return(CHANNEL_DATA, :long, channel.local_id, :string, "w" * (256 * 1024))
      @transport.return(CHANNEL_CLOSE, :long, channel.local_id)
      Timeout.timeout(5) { @ssh.loop(0.1) }

      assert @client.closed?
      assert !@ssh.listeners.key?(@client)
    end

    def test_session_close_should_not_send_data_after_eof_when_a_forwarded_socket_still_has_unread_data
      channel = channel_in_session
      @peer.write("x" * 100)
      @client.fill
      # the server answers our CHANNEL_CLOSE with its own
      transport = @transport
      transport.define_singleton_method(:enqueue_message) do |message|
        transport.return(CHANNEL_CLOSE, :long, channel.local_id) if message.to_s.getbyte(0) == CHANNEL_CLOSE
      end

      assert_nothing_raised { Timeout.timeout(5) { @ssh.close } }
    end

    def test_forwarded_channel_should_send_data_already_read_from_the_local_socket_before_eof
      channel = prepared_channel(remote_window: 0x20000)
      @peer.write("queued")
      @client.fill
      channel.process
      @peer.write("buffered")
      @client.fill
      @peer.write("unread")
      channel.eof!

      channel.process
      channel.process

      assert @session.reading_paused?(@client)
      sent = @session.sent.map { |msg| [msg.read_byte, msg.read_long, msg.read_string] }
      assert_equal [[CHANNEL_DATA, 1, "queued"], [CHANNEL_DATA, 1, "buffered"], [CHANNEL_EOF, 1, nil]], sent
    end

    def teardown
      [@client, @peer, @transport_socket, @transport_peer].compact.reject(&:closed?).each(&:close)
    end

    private

    class ForwardingSession
      attr_reader :sent

      def initialize
        @sent = []
        @paused = {}
      end

      def logger; end

      def options
        {}
      end

      def on_open_channel(*); end

      def listen_to(io)
        (@listening ||= {})[io] = true
      end

      def stop_listening_to(io)
        @listening.delete(io)
        @paused.delete(io)
      end

      def listening?(io)
        @listening.key?(io)
      end

      def pause_reading(io)
        @paused[io] = true
      end

      def resume_reading(io)
        @paused.delete(io)
      end

      def reading_paused?(io)
        @paused.key?(io)
      end

      def send_message(msg)
        @sent << Net::SSH::Buffer.new(msg.to_s)
      end
    end

    # A real Session over a mock transport whose socket is a quiet socketpair,
    # so the event loop selects on real IO.
    def channel_in_session
      @transport_socket, @transport_peer = UNIXSocket.pair
      @transport_socket.extend(Net::SSH::Transport::PacketStream)
      @transport = MockTransport.new(socket: @transport_socket)
      @transport.stubs(:rekey_as_needed)
      @transport.expect { |_t, p| assert_equal CHANNEL_CLOSE, p.type }
      @ssh = Net::SSH::Connection::Session.new(@transport, {})
      @client, @peer = UNIXSocket.pair
      channel = Net::SSH::Connection::Channel.new(@ssh, "direct-tcpip", 0)
      @ssh.channels[channel.local_id] = channel
      @ssh.forward.send(:prepare_client, @client, channel, :local)
      channel.do_open_confirmation(1, 0x20000, 0x8000)
      channel
    end

    def prepared_channel(remote_window:)
      @session = ForwardingSession.new
      @client, @peer = UNIXSocket.pair
      channel = Net::SSH::Connection::Channel.new(@session, "direct-tcpip", 0, 0x8000, 0x20000)
      Net::SSH::Service::Forward.new(@session).send(:prepare_client, @client, channel, :local)
      channel.do_open_confirmation(1, remote_window, 0x8000)
      channel
    end
  end
end
