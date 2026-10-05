require 'common'
require 'net/ssh/transport/server_version'
require 'timeout'

module Transport
  class TestServerVersion < NetSSHTest
    def test_1_99_server_version_should_be_acceptible
      s = subject(socket(true, "SSH-1.99-Testing_1.0\r\n"))
      assert s.header.empty?
      assert_equal "SSH-1.99-Testing_1.0", s.version
    end

    def test_2_0_server_version_should_be_acceptible
      s = subject(socket(true, "SSH-2.0-Testing_1.0\r\n"))
      assert s.header.empty?
      assert_equal "SSH-2.0-Testing_1.0", s.version
    end

    def test_trailing_whitespace_should_be_preserved
      # some servers, like Mocana, send a version string with trailing
      # spaces, which are significant when exchanging keys later.
      s = subject(socket(true, "SSH-2.0-Testing_1.0    \r\n"))
      assert_equal "SSH-2.0-Testing_1.0    ", s.version
    end

    def test_unacceptible_server_version_should_raise_exception
      assert_raises(Net::SSH::Exception) { subject(socket(false, "SSH-1.4-Testing_1.0\r\n")) }
    end

    def test_unexpected_server_close_should_raise_exception
      assert_raises(Net::SSH::Disconnect) { subject(socket(false, "\r\nDestination server does not have Ssh activated.\r\nContact Cisco Systems, Inc to purchase a\r\nlicense key to activate Ssh.\r\n", true)) }
    end

    def test_header_lines_should_be_accumulated
      s = subject(socket(true, "Welcome\r\nAnother line\r\nSSH-2.0-Testing_1.0\r\n"))
      assert_equal "Welcome\r\nAnother line\r\n", s.header
      assert_equal "SSH-2.0-Testing_1.0", s.version
    end

    def test_server_disconnect_should_raise_exception
      assert_raises(Net::SSH::Disconnect) { subject(socket(false, "SSH-2.0-Aborting")) }
    end

    def test_overlong_line_should_raise_exception
      error = assert_raises(Net::SSH::Exception) { negotiate_with("A" * 8193) }
      assert_match(/exceeds 8192 bytes/, error.message)
    end

    def test_too_many_header_lines_should_raise_exception
      error = assert_raises(Net::SSH::Exception) { negotiate_with("#{"banner\r\n" * 1024}SSH-2.0-Testing_1.0\r\n") }
      assert_match(/first 1024 lines/, error.message)
    end

    def test_timeout_should_cover_the_whole_banner
      assert_raises(Net::SSH::ConnectionTimeout) { negotiate_with("Welcome\r\n", timeout: 0.2) }
    end

    private

    def negotiate_with(server_output, timeout: 5)
      client, server = UNIXSocket.pair
      writer = Thread.new { server.write(server_output) rescue nil } # rubocop:disable Style/RescueModifier
      Timeout.timeout(timeout + 5) { Net::SSH::Transport::ServerVersion.new(client, nil, timeout) }
    ensure
      client&.close
      server&.close
      writer&.join
    end

    def socket(good, version_header, raise_eot = false)
      socket = mock("socket")

      socket.expects(:write).with("#{Net::SSH::Transport::ServerVersion::PROTO_VERSION}\r\n")
      socket.expects(:flush)

      data = version_header.split('')
      recv_times = data.length
      recv_times += 1 if data[-1] != "\n"

      if raise_eot
        socket.expects(:readpartial).with(1).times(recv_times + 1).returns(*data).then.raises(EOFError, 'end of file reached')
      else
        socket.expects(:readpartial).with(1).times(recv_times).returns(*data).then.returns(nil)
      end

      socket
    end

    def subject(socket)
      Net::SSH::Transport::ServerVersion.new(socket, nil)
    end
  end
end
