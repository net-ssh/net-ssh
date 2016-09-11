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
    [localhost, user, {:keys => @key_id_rsa}.merge(options)]
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

  def test_transport_close_should_remote_close_channels
    setup_ssh_env do
      Net::SSH.start(*ssh_start_params) do |ssh|
        channel = ssh.open_channel do ||
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
end
