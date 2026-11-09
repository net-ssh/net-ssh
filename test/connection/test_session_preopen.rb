require_relative '../common'
require 'net/ssh/connection/session'

module Connection
  class TestSessionPreopen < NetSSHTest
    include Net::SSH::Connection::Constants

    def test_without_option_should_not_open_spare_channels
      session(preopen_channels: false)
      2.times { session.open_channel }
      process_times(2)
      assert_equal [[CHANNEL_OPEN, 0], [CHANNEL_OPEN, 1]], sent_summary
    end

    def test_first_open_channel_should_open_normally_and_then_a_spare
      channel = session.open_channel
      assert_equal 0, channel.local_id
      process_times(2)
      assert_equal [[CHANNEL_OPEN, 0], [CHANNEL_OPEN, 1]], sent_summary
      assert_equal "session", sent.last[:channel_type]
      assert_equal 0x200000, sent.last[:window_size]
      assert_equal 1, session.channels.size
    end

    def test_confirmed_spare_should_be_handed_out_and_confirmed_from_event_loop
      open_and_confirm_spare(remote_id: 42)
      sent.clear

      confirmed = nil
      channel = session.open_channel do |ch|
        confirmed = ch.remote_id
        ch.exec("true")
      end
      assert_equal 1, channel.local_id
      assert_nil confirmed, "callback should not be invoked immediately"
      assert_nil channel.remote_id
      assert sent.empty?, "no CHANNEL_OPEN should be sent for the handed out spare"

      process_times(2)
      assert_equal 42, confirmed
      assert_equal 0x30000, channel.remote_maximum_window_size
      assert_equal 0x9000, channel.remote_maximum_packet_size
      assert_equal [[CHANNEL_REQUEST, 42], [CHANNEL_OPEN, 2]], sent_summary
    end

    def test_unconfirmed_spare_should_be_handed_out_and_confirmed_when_reply_arrives
      session.open_channel
      process_times(2)
      sent.clear

      confirmed = nil
      channel = session.open_channel { |ch| confirmed = ch.remote_id }
      assert_equal 1, channel.local_id
      process_times(2)
      assert_nil confirmed
      assert_equal [[CHANNEL_OPEN, 2]], sent_summary

      transport.return(CHANNEL_OPEN_CONFIRMATION, :long, 1, :long, 77, :long, 0x20000, :long, 0x8000)
      process_times(2)
      assert_equal 77, confirmed
    end

    def test_refused_spare_should_stop_preopening_without_raising
      session.open_channel
      process_times(2)
      transport.return(CHANNEL_OPEN_FAILURE, :long, 1, :long, 2, :string, "open failed", :string, "")
      process_times(2)
      sent.clear

      channel = session.open_channel
      process_times(2)
      assert_equal 2, channel.local_id
      assert_equal [[CHANNEL_OPEN, 2]], sent_summary
    end

    def test_refused_handed_out_spare_should_fail_like_a_normal_channel
      session.open_channel
      process_times(2)
      failed = nil
      channel = session.open_channel
      channel.on_open_failed { |_ch, code, _reason| failed = code }

      transport.return(CHANNEL_OPEN_FAILURE, :long, 1, :long, 2, :string, "open failed", :string, "")
      process_times(2)
      assert_equal 2, failed
      assert !session.channels.key?(1)
    end

    def test_other_channel_types_should_not_use_the_spare
      open_and_confirm_spare(remote_id: 42)
      sent.clear

      channel = session.open_channel("direct-tcpip", :string, "localhost", :long, 80, :string, "127.0.0.1", :long, 0)
      assert_equal 2, channel.local_id
      session.open_channel("session", :string, "extra")
      process_times(2)
      assert_equal [[CHANNEL_OPEN, 2], [CHANNEL_OPEN, 3]], sent_summary
    end

    def test_spare_should_not_keep_session_busy
      open_and_confirm_spare(remote_id: 42)
      session.channels.clear
      assert !session.busy?(true)
    end

    def test_close_should_drop_unused_spare_without_sending_anything
      open_and_confirm_spare(remote_id: 42)
      session.channels.clear
      sent.clear
      IO.stubs(:select).returns([[], [], []])
      transport.expects(:close)
      session.close
      assert sent.empty?
    end

    def test_reply_for_spare_after_close_should_be_absorbed
      session.open_channel
      process_times(2)
      session.channels.clear
      IO.stubs(:select).returns([[], [], []])
      transport.stubs(:close)
      session.close
      sent.clear

      session.expects(:lwarn).never
      transport.return(CHANNEL_OPEN_CONFIRMATION, :long, 1, :long, 42, :long, 0x20000, :long, 0x8000)
      process_times(2)
      assert sent.empty?, "no new spare should be opened after close"
    end

    def test_remote_close_of_spare_should_be_answered_and_not_reopened_until_needed
      open_and_confirm_spare(remote_id: 42)
      sent.clear

      transport.return(CHANNEL_EOF, :long, 1)
      transport.return(CHANNEL_CLOSE, :long, 1)
      process_times(2)
      process_times(2)
      assert_equal [[CHANNEL_CLOSE, 42]], sent_summary
      sent.clear

      channel = session.open_channel
      process_times(2)
      assert_equal 2, channel.local_id
      assert_equal [[CHANNEL_OPEN, 2], [CHANNEL_OPEN, 3]], sent_summary
    end

    def test_window_adjust_for_spare_should_carry_over_to_handed_out_channel
      open_and_confirm_spare(remote_id: 42)
      transport.return(CHANNEL_WINDOW_ADJUST, :long, 1, :long, 0x1000)
      process_times(2)

      channel = session.open_channel
      process_times(2)
      assert_equal 0x31000, channel.remote_window_size
    end

    private

    def open_and_confirm_spare(remote_id:)
      session.open_channel
      process_times(2)
      transport.return(CHANNEL_OPEN_CONFIRMATION, :long, 1, :long, remote_id, :long, 0x30000, :long, 0x9000)
      process_times(2)
    end

    def sent
      @sent ||= begin
        log = []
        transport.define_singleton_method(:enqueue_message) do |message|
          log << Net::SSH::Packet.new(Net::SSH::Buffer.new(message.to_s))
        end
        log
      end
    end

    # Each sent packet's type with the channel id it names: our local id for CHANNEL_OPEN, the recipient's otherwise.
    def sent_summary
      sent.map { |p| [p.type, p.type == CHANNEL_OPEN ? p[:remote_id] : p[:local_id]] }
    end

    def transport
      @transport ||= MockTransport.new(socket: Object.new.extend(Net::SSH::Transport::PacketStream))
    end

    def session(options = { preopen_channels: true })
      @session ||= Net::SSH::Connection::Session.new(transport, options).tap { sent }
    end

    def process_times(count)
      i = 0
      session.process { (i += 1) < count }
    end
  end
end
