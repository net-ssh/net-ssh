require_relative '../common'
require 'net/ssh/transport/session'
require 'net/ssh/proxy/http'
require 'logger'

# mocha adds #verify to Object, which throws off the host-key-verifier part of
# these tests.

# can't use .include? because ruby18 uses strings and ruby19 uses symbols :/
Object.send(:undef_method, :verify) if Object.instance_methods.any? { |v| v.to_sym == :verify }

module Transport

  class TestSession < NetSSHTest
    include Net::SSH::Transport::Constants

    TEST_HOST = "net.ssh.test"
    TEST_PORT = 22

    def test_constructor_defaults
      assert_equal TEST_HOST, session.host
      assert_equal TEST_PORT, session.port
      assert_instance_of(
        Net::SSH::Verifiers::AcceptNewOrLocalTunnel,
        session.host_key_verifier
      )
    end

    def test_verify_host_key_true_uses_accept_new_or_local_tunnel_verifier
      Kernel.expects(:warn).with(
        'verify_host_key: true is deprecated, use :accept_new_or_local_tunnel'
      )
      assert_instance_of(
        Net::SSH::Verifiers::AcceptNewOrLocalTunnel,
        session(verify_host_key: true).host_key_verifier
      )
    end

    def test_verify_host_key_accept_new_or_local_tunnel_uses_accept_new_or_local_tunnel_verifier
      assert_instance_of(
        Net::SSH::Verifiers::AcceptNewOrLocalTunnel,
        session(verify_host_key: :accept_new_or_local_tunnel).host_key_verifier
      )
    end

    def test_verify_host_key_nil_uses_accept_new_or_local_tunnel_verifier
      assert_instance_of(
        Net::SSH::Verifiers::AcceptNewOrLocalTunnel,
        session(verify_host_key: nil).host_key_verifier
      )
    end

    def test_verify_host_key_very_uses_accept_new_verifier
      Kernel.expects(:warn).with('verify_host_key: :very is deprecated, use :accept_new')
      assert_instance_of(
        Net::SSH::Verifiers::AcceptNew,
        session(verify_host_key: :very).host_key_verifier
      )
    end

    def test_verify_host_key_accept_new_uses_accept_new_verifier
      assert_instance_of(
        Net::SSH::Verifiers::AcceptNew,
        session(verify_host_key: :accept_new).host_key_verifier
      )
    end

    def test_verify_host_key_secure_uses_always_verifier
      Kernel.expects(:warn).with('verify_host_key: :secure is deprecated, use :always')
      assert_instance_of(
        Net::SSH::Verifiers::Always,
        session(verify_host_key: :secure).host_key_verifier
      )
    end

    def test_verify_host_key_false_uses_never_verifier
      Kernel.expects(:warn).with('verify_host_key: false is deprecated, use :never')
      assert_instance_of(
        Net::SSH::Verifiers::Never,
        session(verify_host_key: false).host_key_verifier
      )
    end

    def test_verify_host_key_null_uses_never_verifier
      assert_instance_of(
        Net::SSH::Verifiers::Never,
        session(verify_host_key: :never).host_key_verifier
      )
    end

    def test_unknown_verify_host_key_value_raises_exception_if_value_does_not_respond_to_verify
      assert_raises(ArgumentError) { session(verify_host_key: :bogus).host_key_verifier }
    end

    def test_verify_host_key_value_responding_to_verify_should_pass_muster
      object = stub("thingy", verify: true, verify_signature: true)
      assert_equal object, session(verify_host_key: object).host_key_verifier
    end

    def test_deprecated_host_key_verifier
      Kernel.expects(:warn).with('Warning: verifier without :verify_signature is deprecated')

      object = stub("thingy", verify: true)
      assert_not_nil session(verify_host_key: object).host_key_verifier
    end

    def test_host_as_string_should_return_host_and_ip_when_port_is_default
      session!
      socket.stubs(:peer_ip).returns("1.2.3.4")
      assert_equal "#{TEST_HOST},1.2.3.4", session.host_as_string
    end

    def test_host_as_string_should_return_host_and_ip_with_port_when_port_is_not_default
      session(port: 1234) # force session to be instantiated
      socket.stubs(:peer_ip).returns("1.2.3.4")
      assert_equal "[#{TEST_HOST}]:1234,[1.2.3.4]:1234", session.host_as_string
    end

    def test_host_as_string_should_return_only_host_when_host_is_ip
      session!(host: "1.2.3.4")
      socket.stubs(:peer_ip).returns("1.2.3.4")
      assert_equal "1.2.3.4", session.host_as_string
    end

    def test_host_as_string_should_return_only_host_and_port_when_host_is_ip_and_port_is_not_default
      session!(host: "1.2.3.4", port: 1234)
      socket.stubs(:peer_ip).returns("1.2.3.4")
      assert_equal "[1.2.3.4]:1234", session.host_as_string
    end

    def test_host_as_string_should_return_only_host_when_proxy_command_is_set
      session!(host: "1.2.3.4")
      socket.stubs(:peer_ip).returns(Net::SSH::Transport::PacketStream::PROXY_COMMAND_HOST_IP)
      assert_equal "1.2.3.4", session.host_as_string
    end

    def test_host_as_string_should_return_only_host_and_port_when_host_is_ip_and_port_is_not_default_and_proxy_command_is_set
      session!(host: "1.2.3.4", port: 1234)
      socket.stubs(:peer_ip).returns(Net::SSH::Transport::PacketStream::PROXY_COMMAND_HOST_IP)
      assert_equal "[1.2.3.4]:1234", session.host_as_string
    end

    def test_close_should_cleanup_and_close_socket
      session!
      socket.expects(:cleanup)
      socket.expects(:close)
      session.close
    end

    def test_service_request_should_return_buffer
      assert_equal "\005\000\000\000\004sftp", session.service_request('sftp').to_s
    end

    def test_rekey_when_kex_is_pending_should_do_nothing
      algorithms.stubs(pending?: true)
      algorithms.expects(:rekey!).never
      session.rekey!
    end

    def test_rekey_when_no_kex_is_pending_should_initiate_rekey_and_block_until_it_completes
      algorithms.stubs(pending?: false)
      algorithms.expects(:rekey!)
      session.expects(:wait).yields
      algorithms.expects(:initialized?).returns(true)
      session.rekey!
    end

    def test_rekey_as_needed_when_kex_is_pending_should_do_nothing
      session!
      algorithms.stubs(pending?: true)
      socket.expects(:if_needs_rekey?).never
      session.rekey_as_needed
    end

    def test_rekey_as_needed_when_no_kex_is_pending_and_no_rekey_is_needed_should_do_nothing
      session!
      algorithms.stubs(pending?: false)
      socket.stubs(if_needs_rekey?: false)
      session.expects(:rekey!).never
      session.rekey_as_needed
    end

    def test_rekey_as_needed_when_no_kex_is_pending_and_rekey_is_needed_should_initiate_rekey_and_block
      session!
      algorithms.stubs(pending?: false)
      socket.expects(:if_needs_rekey?).yields
      session.expects(:rekey!)
      session.rekey_as_needed
    end

    def test_peer_should_return_hash_of_info_about_peer
      session!
      socket.stubs(peer_ip: "1.2.3.4")
      assert_equal({ ip: "1.2.3.4", port: TEST_PORT, host: TEST_HOST, canonized: "net.ssh.test,1.2.3.4" }, session.peer)
    end

    def test_next_message_should_block_until_next_message_is_available
      session.expects(:poll_message).with(:block)
      session.next_message
    end

    def test_poll_message_should_query_next_packet_using_the_given_blocking_parameter
      session!
      socket.expects(:next_packet).with(:blocking_parameter, nil).returns(nil)
      session.poll_message(:blocking_parameter)
    end

    def test_poll_message_should_query_next_packet_using_the_timeout_option
      session!(timeout: 7)
      socket.expects(:next_packet).with(:nonblock, 7).returns(nil)
      session.poll_message
    end

    def test_poll_message_should_default_to_non_blocking
      session!
      socket.expects(:next_packet).with(:nonblock, nil).returns(nil)
      session.poll_message
    end

    def test_poll_message_should_silently_handle_disconnect_packets
      session!
      socket.expects(:next_packet).returns(P(:byte, DISCONNECT, :long, 1, :string, "testing", :string, ""))
      assert_raises(Net::SSH::Disconnect) { session.poll_message }
    end

    def test_poll_message_should_silently_handle_ignore_packets
      session!
      socket.expects(:next_packet).times(2).returns(P(:byte, IGNORE, :string, "test"), nil)
      assert_nil session.poll_message
    end

    def test_poll_message_should_silently_handle_unimplemented_packets
      session!
      socket.expects(:next_packet).times(2).returns(P(:byte, UNIMPLEMENTED, :long, 15), nil)
      assert_nil session.poll_message
    end

    def test_poll_message_should_silently_handle_debug_packets_with_always_display
      session!
      socket.expects(:next_packet).times(2).returns(P(:byte, DEBUG, :bool, true, :string, "testing", :string, ""), nil)
      assert_nil session.poll_message
    end

    def test_poll_message_should_silently_handle_debug_packets_without_always_display
      session!
      socket.expects(:next_packet).times(2).returns(P(:byte, DEBUG, :bool, false, :string, "testing", :string, ""), nil)
      assert_nil session.poll_message
    end

    def test_poll_message_should_silently_handle_kexinit_packets
      session!
      packet = P(:byte, KEXINIT, :raw, "lasdfalksdjfa;slkdfja;slkfjsdfaklsjdfa;df")
      socket.expects(:next_packet).times(2).returns(packet, nil)
      algorithms.expects(:accept_kexinit).with(packet)
      assert_nil session.poll_message
    end

    def test_poll_message_should_return_other_packets
      session!
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      socket.expects(:next_packet).returns(packet)
      assert_equal packet, session.poll_message
    end

    def test_poll_message_should_enqueue_packets_when_algorithm_disallows_packet
      session!
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      algorithms.stubs(:allow?).with(packet).returns(false)
      socket.expects(:next_packet).times(2).returns(packet, nil)
      assert_nil session.poll_message
      assert_equal [packet], session.queue
    end

    def test_poll_message_should_read_from_queue_when_next_in_queue_is_allowed_and_consume_queue_is_true
      session!
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      session.push(packet)
      socket.expects(:next_packet).never
      assert_equal packet, session.poll_message
      assert session.queue.empty?
    end

    def test_poll_message_should_not_read_from_queue_when_next_in_queue_is_not_allowed
      session!
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      algorithms.stubs(:allow?).with(packet).returns(false)
      session.push(packet)
      socket.expects(:next_packet).returns(nil)
      assert_nil session.poll_message
      assert_equal [packet], session.queue
    end

    def test_poll_message_should_not_read_from_queue_when_consume_queue_is_false
      session!
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      session.push(packet)
      socket.expects(:next_packet).returns(nil)
      assert_nil session.poll_message(:nonblock, false)
      assert_equal [packet], session.queue
    end

    def test_wait_with_block_should_return_immediately_if_block_returns_truth
      session.expects(:poll_message).never
      session.wait { true }
    end

    def test_wait_should_not_consume_queue_on_reads
      n = 0
      session.expects(:poll_message).with(:nonblock, false).returns(nil)
      session.wait { (n += 1) > 1 }
    end

    def test_wait_without_block_should_return_after_first_read
      session.expects(:poll_message).returns(nil)
      session.wait
    end

    def test_wait_should_enqueue_packets
      session!

      p1 = P(:byte, SERVICE_REQUEST, :string, "test")
      p2 = P(:byte, SERVICE_ACCEPT, :string, "test")
      socket.expects(:next_packet).times(2).returns(p1, p2)

      n = 0
      session.wait { (n += 1) > 2 }
      assert_equal [p1, p2], session.queue
    end

    def test_push_should_enqueue_packet
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      session.push(packet)
      assert_equal [packet], session.queue
    end

    def test_send_message_should_delegate_to_socket
      session!
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      socket.expects(:send_packet).with(packet)
      session.send_message(packet)
    end

    def test_enqueue_message_should_delegate_to_socket
      session!
      packet = P(:byte, SERVICE_ACCEPT, :string, "test")
      socket.expects(:enqueue_packet).with(packet)
      session.enqueue_message(packet)
    end

    def test_configure_client_should_pass_options_to_socket_client_state
      session.configure_client compression: :standard
      assert_equal :standard, socket.client.compression
    end

    def test_configure_server_should_pass_options_to_socket_server_state
      session.configure_server compression: :standard
      assert_equal :standard, socket.server.compression
    end

    def test_hint_should_set_hint_on_socket
      assert !socket.hints[:authenticated]
      session.hint :authenticated
      assert socket.hints[:authenticated]
    end

    class TestLogger < Logger
      def initialize
        @strio = StringIO.new
        super(@strio)
      end

      def messages
        @strio.string
      end
    end

    def test_log_correct_debug_with_proxy
      logger = TestLogger.new
      proxy = Net::SSH::Proxy::HTTP.new("")

      session!(logger: logger, proxy: proxy)
      assert_match "establishing connection to #{TEST_HOST}:#{TEST_PORT} through proxy", logger.messages
    end

    def test_log_correct_debug_without_proxy
      logger = TestLogger.new

      session!(logger: logger)
      assert_match "establishing connection to #{TEST_HOST}:#{TEST_PORT}", logger.messages
    end

    private

    def socket
      @socket ||= stub("socket", hints: {})
    end

    def server_version
      @server_version ||= stub("server_version")
    end

    def algorithms
      @algorithms ||= stub("algorithms", initialized?: true, allow?: true, start: true)
    end

    def session(options={})
      @session ||= begin
        host = options.delete(:host) || TEST_HOST
        if (proxy = options[:proxy])
          proxy.stubs("open").returns(socket)
        else
          Socket.stubs(:tcp).with(host, options[:port] || TEST_PORT, nil, nil, { connect_timeout: options[:timeout] }).returns(socket)
        end
        Net::SSH::Transport::ServerVersion.stubs(:new).returns(server_version)
        Net::SSH::Transport::Algorithms.stubs(:new).returns(algorithms)

        Net::SSH::Transport::Session.new(host, options)
      end
    end
    # a simple alias to make the tests more self-documenting. the bang
    # version makes it look more like the session is being instantiated
    alias session! session
  end

end
