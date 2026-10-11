require_relative '../common'
require 'net/ssh/authentication/agent'
require 'io/wait'
require 'net/ssh/connection/channel'
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
      assert @session.paused?(@client)

      channel.do_data("reply")
      @client.send_pending
      assert_equal "reply", @peer.read_nonblock(100)

      channel.do_window_adjust(100)
      channel.process
      assert_equal 0, channel.output.length
      assert !@session.paused?(@client)
    end

    def test_forwarded_channel_should_grant_window_only_for_bytes_written_to_the_socket
      channel = prepared_channel(remote_window: 10)

      channel.do_data("x" * 0x10001)
      assert_empty @session.sent

      @client.send_pending
      written = @peer.read_nonblock(0x20000).length
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
      assert @session.paused?(@client)

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

    def teardown
      [@client, @peer].compact.each(&:close)
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

      def paused?(io)
        @paused.key?(io)
      end

      def send_message(msg)
        @sent << Net::SSH::Buffer.new(msg.to_s)
      end
    end

    def prepared_channel(remote_window:)
      @session = ForwardingSession.new
      @client, @peer = UNIXSocket.pair
      channel = Net::SSH::Connection::Channel.new(@session, "direct-tcpip", 0)
      Net::SSH::Service::Forward.new(@session).send(:prepare_client, @client, channel, :local)
      channel.do_open_confirmation(1, remote_window, 0x8000)
      channel
    end
  end
end
