require_relative 'common'
require 'net/ssh/buffer'
require 'net/ssh'
require 'net/ssh/proxy/command'
require 'timeout'
require 'tempfile'

class TestChannel < NetSSHTest
  include IntegrationTestHelpers

  def localhost
    'localhost'
  end

  def user
    'net_ssh_1'
  end

  def ssh_start_params(options = {})
    [localhost, user, { keys: @key_id_rsa }.merge(options)]
  end

  def setup_ssh_env(&block)
    tmpdir do |dir|
      @key_id_rsa = "#{dir}/id_rsa"
      sh "rm -rf #{@key_id_rsa} #{@key_id_rsa}.pub"
      sh "ssh-keygen -q -f #{@key_id_rsa} -t rsa -N ''"
      set_authorized_key(user,"#{@key_id_rsa}.pub")
      yield
    end
  end

  def ssh_exec(ssh, command, channel_success_handler, &block)
    ssh.open_channel do |channel|
      channel.exec(command) do |_ch, success|
        raise "could not execute command: #{command.inspect}" unless success

        channel_success_handler.call
        channel.on_data do |ch2, data|
          yield(ch2, :stdout, data)
        end

        channel.on_extended_data do |ch2, _type, data|
          yield(ch2, :stderr, data)
        end
      end
    end
  end

  def test_transport_close_before_channel_close_should_raise
    setup_ssh_env do
      proxy = Net::SSH::Proxy::Command.new("/bin/nc localhost 22")
      res = nil
      Net::SSH.start(*ssh_start_params(proxy: proxy)) do |ssh|
        channel_success_handler = lambda do
          sleep(0.1)
          system("killall /bin/nc")
        end
        channel = ssh_exec(ssh, "echo Begin ; sleep 100 ; echo End", channel_success_handler) do |ch, _type, data|
          ch[:result] ||= ""
          ch[:result] << data
        end
        assert_raises(IOError) { channel.wait }
        res = channel[:result]
        assert_equal(res, "Begin\n")
      end
      assert_equal(res, "Begin\n")
    end
  end

  def test_transport_close_after_channel_close_should_not_raise
    setup_ssh_env do
      proxy = Net::SSH::Proxy::Command.new("/bin/nc localhost 22")
      res = nil
      Net::SSH.start(*ssh_start_params(proxy: proxy)) do |ssh|
        channel_success_handler = lambda do
          sleep(0.1)
          system("killall /bin/nc")
        end
        channel = ssh_exec(ssh, "echo Hello!", channel_success_handler) do |ch, _type, data|
          ch[:result] ||= ""
          ch[:result] << data
        end
        channel.wait
        res = channel[:result]
        assert_equal(res, "Hello!\n")
      end
      assert_equal(res, "Hello!\n")
    end
  end

  def test_transport_close_should_remote_close_channels
    setup_ssh_env do
      Net::SSH.start(*ssh_start_params) do |ssh|
        channel = ssh.open_channel do
          ssh.transport.socket.close
        end
        remote_closed = nil
        begin
          channel.wait
        rescue StandardError
          remote_closed = channel.remote_closed?
        end
        assert_equal remote_closed, true
      end
    end
  end

  def test_channel_should_set_environment_variables_on_remote
    setup_ssh_env do
      start_sshd_7_or_later(config: 'AcceptEnv foo baz') do |_pid, port|
        Timeout.timeout(20) do
          # We have our own sshd, give it a chance to come up before
          # listening.
          proxy = Net::SSH::Proxy::Command.new("/bin/nc localhost #{port}")
          res = nil
          Net::SSH.start(*ssh_start_params(port: port, proxy: proxy, set_env: { foo: 'bar', baz: 'whale will' })) do |ssh|
            channel_success_handler = lambda do
              sleep(0.1)
              system("killall /bin/nc")
            end
            channel = ssh_exec(ssh, "echo A:$foo; echo B:$baz", channel_success_handler) do |ch, _type, data|
              ch[:result] ||= ""
              ch[:result] << data
            end
            channel.wait
            res = channel[:result]
            assert_equal(res, "A:bar\nB:whale will\n")
          end
          assert_equal(res, "A:bar\nB:whale will\n")
        rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Net::SSH::Proxy::ConnectError
          sleep 0.25
          retry
        end
      end
    end
  end
end
