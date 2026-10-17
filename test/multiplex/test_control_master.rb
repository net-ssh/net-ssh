require_relative '../common'
require_relative 'fake_master'
require 'net/ssh'

module NetSSH
  class TestControlMaster < NetSSHTest
    def setup
      skip "ControlMaster needs UNIX sockets" if Gem.win_platform?
      @dir = Dir.mktmpdir('cm')
      @path = File.join(@dir, 'ctl')
      @log = StringIO.new
      @logger = Logger.new(@log)
      @logger.level = Logger::DEBUG
    end

    def teardown
      @master&.stop
      FileUtils.rm_rf(@dir) if @dir
    end

    def start(options = {}, &block)
      Net::SSH.start('example.com', 'alice', { config: false, logger: @logger, control_master: :auto, control_path: @path }.merge(options), &block)
    end

    def expect_direct_connection
      direct = mock('direct connection')
      direct.stubs(:closed?).returns(true)
      Net::SSH.expects(:connect_directly).with('example.com', 'alice', anything).returns(direct)
      direct
    end

    def test_exec_through_master
      @master = FakeMaster.new(@path, output: "hi\n", exit_status: 3)
      Net::SSH.expects(:connect_directly).never

      start do |ssh|
        assert_instance_of Net::SSH::Multiplex::ProxyTransport, ssh.transport
        result = ssh.exec!("echo hi")
        assert_equal "hi\n", result
        assert_equal 3, result.exitstatus
      end
      assert_equal 1, @master.connections
      assert_includes @log.string, "using ControlMaster at #{@path}"
    end

    def test_old_protocol_version_falls_back
      @master = FakeMaster.new(@path, mode: :old_version)
      direct = expect_direct_connection

      assert_equal direct, start
      assert_includes @log.string, "unsupported mux protocol version 3"
    end

    def test_refused_proxy_falls_back
      @master = FakeMaster.new(@path, mode: :refuse)
      direct = expect_direct_connection

      assert_equal direct, start
      assert_includes @log.string, "master refused proxy request: Permission denied"
    end

    def test_missing_socket_falls_back
      direct = expect_direct_connection

      assert_equal direct, start
      assert_includes @log.string, "No such file or directory"
    end

    def test_stale_socket_falls_back
      UNIXServer.new(@path).close
      direct = expect_direct_connection

      assert_equal direct, start
      assert_includes @log.string, "Connection refused"
    end

    def test_silent_master_times_out_and_falls_back
      @master = FakeMaster.new(@path, mode: :silent)
      direct = expect_direct_connection

      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_equal direct, start(timeout: 0.3)
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2
      assert_includes @log.string, "timed out"
    end

    def test_master_of_another_user_falls_back
      @master = FakeMaster.new(@path)
      Process.stubs(:euid).returns(Process.uid + 1)
      direct = expect_direct_connection

      assert_equal direct, start
      assert_includes @log.string, "owned by uid #{Process.uid}"
    end

    def test_control_path_none_falls_back
      direct = expect_direct_connection
      Net::SSH::Multiplex::Client.expects(:new).never

      assert_equal direct, start(control_path: 'none')
    end

    def test_remote_forwarding_raises
      @master = FakeMaster.new(@path)
      start do |ssh|
        assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.forward.remote(8080, 'localhost', 80) }
        assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.forward.cancel_remote(8080) }
        assert_equal "hello\n", ssh.exec!("true")
      end
      refute_includes @master.received_types, Net::SSH::Connection::Constants::GLOBAL_REQUEST
    end

    def test_global_request_raises
      @master = FakeMaster.new(@path)
      start do |ssh|
        error = assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.send_global_request("keepalive@openssh.com") }
        assert_match(/keepalive@openssh.com/, error.message)
      end
    end

    def test_agent_forwarding_request_raises
      @master = FakeMaster.new(@path)
      start do |ssh|
        channel = ssh.open_channel
        ssh.loop { channel.remote_id.nil? }
        assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.forward.agent(channel) }
      end
    end

    def test_forward_agent_option_conflicts
      assert_raises(ArgumentError) { start(forward_agent: true) }
    end

    def test_keepalive_is_disabled
      @master = FakeMaster.new(@path)
      start(keepalive: true, keepalive_interval: 0.05) do |ssh|
        refute ssh.options[:keepalive]
        3.times do
          sleep 0.06
          ssh.process(0.01)
        end
        ssh.exec!("true")
      end
      refute_includes @master.received_types, Net::SSH::Connection::Constants::GLOBAL_REQUEST
      assert_includes @log.string, "keepalive is left to the ControlMaster"
    end

    def test_warns_about_explicit_master_owned_options
      @master = FakeMaster.new(@path)
      start(password: 'secret', verify_host_key: :always, port: 22, &:close)
      assert_match(/WARN.*ignoring password, verify_host_key, the ControlMaster's own settings apply/, @log.string)
    end

    def test_ssh_config_control_path_is_used
      @master = FakeMaster.new(File.join(@dir, 'alice@example.com:2222'))
      config = File.join(@dir, 'config')
      File.write(config, "Host example.com\n  Port 2222\n  ControlMaster auto\n  ControlPath #{@dir}/%r@%h:%p\n")
      Net::SSH.expects(:connect_directly).never

      Net::SSH.start('example.com', 'alice', config: config, logger: @logger, control_master: :auto, &:close)
      assert_equal 1, @master.connections
    end

    def test_ssh_config_control_master_alone_does_not_enable_it
      @master = FakeMaster.new(@path)
      config = File.join(@dir, 'config')
      File.write(config, "Host *\n  ControlMaster yes\n  ControlPath #{@path}\n")
      direct = expect_direct_connection
      Net::SSH::Multiplex::Client.expects(:new).never

      assert_equal direct, Net::SSH.start('example.com', 'alice', config: config, logger: @logger)
      assert_equal 0, @master.connections
    end

    def test_default_never_touches_the_socket
      @master = FakeMaster.new(@path)
      direct = expect_direct_connection
      Net::SSH::Multiplex::Client.expects(:new).never

      assert_equal direct, Net::SSH.start('example.com', 'alice', config: false, logger: @logger, control_path: @path)
      assert_equal 0, @master.connections
    end

    def test_control_master_false
      @master = FakeMaster.new(@path)
      direct = expect_direct_connection

      assert_equal direct, start(control_master: false)
      assert_equal 0, @master.connections
    end

    def test_invalid_control_master_value
      assert_raises(ArgumentError) { start(control_master: :yes) }
    end
  end
end
