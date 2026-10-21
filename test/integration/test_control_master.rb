# frozen_string_literal: true

require_relative 'common'
require 'net/ssh'
require 'stringio'
require 'tmpdir'

# Runs sessions through a real OpenSSH ControlMaster started with ssh -M.
class TestControlMaster < NetSSHTest
  include IntegrationTestHelpers

  def setup
    @dir = Dir.mktmpdir('cm')
    @key = "#{@dir}/id_rsa"
    @control_path = "#{@dir}/ctl"
    ssh_keygen @key, 'rsa'
    set_authorized_key(user, "#{@key}.pub")
    sh "ssh #{ssh_options} -o ControlMaster=yes -o ControlPersist=600 -fN #{user}@#{localhost}"
  end

  def teardown
    stop_master
    FileUtils.rm_rf(@dir)
  end

  def ssh_options
    "-F /dev/null -i #{@key} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o LogLevel=ERROR " \
      "-o UserKnownHostsFile=#{@dir}/known_hosts -o ControlPath=#{@control_path}"
  end

  def stop_master
    system("ssh #{ssh_options} -O exit #{user}@#{localhost} 2>/dev/null")
  end

  def start(options = {}, &block)
    Net::SSH.start(localhost, user, { config: false, control_master: :auto, control_path: @control_path }.merge(options), &block)
  end

  def test_exec
    start do |ssh|
      assert_instance_of Net::SSH::Multiplex::ProxyTransport, ssh.transport
      result = ssh.exec!("echo $USER; exit 3")
      assert_equal "#{user}\n", result
      assert_equal 3, result.exitstatus
      assert_equal "again\n", ssh.exec!("echo again")
    end
  end

  def test_concurrent_channels_with_pty
    start do |ssh|
      outputs = Hash.new { |h, k| h[k] = String.new }
      3.times do |i|
        ssh.open_channel do |ch|
          ch.request_pty if i.zero?
          ch.exec("tty -s && echo tty#{i} || echo notty#{i}") do |_, success|
            assert success
            ch.on_data { |_, data| outputs[i] << data }
          end
        end
      end
      ssh.loop
      assert_equal "tty0\r\n", outputs[0]
      assert_equal "notty1\n", outputs[1]
      assert_equal "notty2\n", outputs[2]
    end
  end

  def test_local_forward
    server = TCPServer.new('127.0.0.1', 0)
    Thread.new do
      client = server.accept
      client.write(client.gets.upcase)
      client.close
    end
    start do |ssh|
      port = ssh.forward.local(0, '127.0.0.1', server.addr[1])
      reply = nil
      Thread.new do
        socket = TCPSocket.new('127.0.0.1', port)
        socket.puts "hello"
        reply = socket.gets
        socket.close
      end
      ssh.loop(0.1) { reply.nil? }
      assert_equal "HELLO\n", reply
    end
  ensure
    server&.close
  end

  def test_sftp
    begin
      require 'net/sftp'
    rescue LoadError
      skip "net-sftp is not installed"
    end
    remote = "/tmp/net-ssh-control-master-#{Process.pid}.txt"
    start do |ssh|
      ssh.sftp.upload!(StringIO.new("over the master\n"), remote)
      assert_equal "over the master\n", ssh.sftp.download!(remote)
      ssh.sftp.remove!(remote)
    end
  end

  def test_unsupported_requests_raise_and_leave_the_session_usable
    start(keepalive: true, keepalive_interval: 1) do |ssh|
      assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.forward.remote(0, 'localhost', 22) }
      assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.send_global_request('keepalive@openssh.com') }
      deadline = Time.now + 2.5
      ssh.loop(0.5) { Time.now < deadline }
      assert_equal "still here\n", ssh.exec!("sleep 1.5; echo still here")
    end
  end

  def test_falls_back_without_a_master
    stop_master
    start(keys: [@key], user_known_hosts_file: "#{@dir}/known_hosts", verify_host_key: :never) do |ssh|
      assert_instance_of Net::SSH::Transport::Session, ssh.transport
      assert_equal "direct\n", ssh.exec!("echo direct")
    end
  end

  # The event loop reports the closed socket as it does for a direct
  # connection whose server goes away.
  def test_master_exit_ends_the_session
    start do |ssh|
      assert_equal "up\n", ssh.exec!("echo up")
      stop_master
      assert_raises(Net::SSH::Disconnect, IOError) { ssh.exec!("echo gone") }
    end
  end
end
