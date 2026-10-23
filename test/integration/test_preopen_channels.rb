require_relative 'common'
require 'net/ssh'
require 'timeout'

class TestPreopenChannels < NetSSHTest
  include IntegrationTestHelpers

  def start(options = {}, &block)
    Net::SSH.start(localhost, user, { password: 'foopwd', preopen_channels: true, non_interactive: true }.merge(options), &block)
  end

  def spare(ssh)
    ssh.instance_variable_get(:@spare_channel)
  end

  def test_sequential_commands_use_the_spare
    start do |ssh|
      assert_equal "1\n", ssh.exec!("echo 1")
      ssh.loop(0.1) { spare(ssh).remote_id.nil? }
      spare_id = spare(ssh).local_id

      channel = ssh.open_channel { |ch| ch.exec("echo 2; exit 7") { ch.on_data { |_, data| ch[:out] = data } } }
      channel.on_request("exit-status") { |_, data| channel[:status] = data.read_long }
      channel.wait
      assert_equal spare_id, channel.local_id
      assert_equal "2\n", channel[:out]
      assert_equal 7, channel[:status]

      5.times { |i| assert_equal "#{i}\n", ssh.exec!("echo #{i}") }
    end
  end

  def test_concurrent_channels
    start do |ssh|
      ssh.exec!("true")
      outputs = Array.new(3) { String.new }
      3.times { |i| ssh.exec("echo #{i}") { |_, _, data| outputs[i] << data } }
      ssh.loop
      assert_equal(3.times.map { |i| "#{i}\n" }, outputs)
    end
  end

  def test_falls_back_when_server_refuses_the_spare
    config = File.read('/etc/ssh/sshd_config').split("\n").grep_v(/^\s*MaxSessions/i) + ["MaxSessions 1"]
    start_sshd_7_or_later(config: config) do |_pid, port|
      Timeout.timeout(10) do
        start(port: port, user_known_hosts_file: '/dev/null', verify_host_key: :never) do |ssh|
          assert_equal "a\n", ssh.exec!("echo a")
          ssh.loop(0.1) { spare(ssh) }
          assert_nil spare(ssh)
          assert_equal "b\n", ssh.exec!("echo b")
          assert_equal "c\n", ssh.exec!("echo c")
        end
      rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        sleep 0.25
        retry
      end
    end
  end

  def test_close_with_unused_spare_does_not_wait_for_it
    start do |ssh|
      ssh.exec!("true")
      ssh.loop(0.1) { spare(ssh).remote_id.nil? }
      ssh.close
      assert ssh.closed?
    end
  end
end
