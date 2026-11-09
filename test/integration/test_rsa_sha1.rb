require_relative 'common'
require 'tmpdir'
require 'timeout'
require 'net/ssh'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
class TestRSASHA1 < NetSSHTest
  include IntegrationTestHelpers

  RSA_HOST_KEY = "HostKey /etc/ssh/ssh_host_rsa_key".freeze

  def connect(config_lines, options = {})
    start_sshd_7_or_later(config: config_lines) do |_pid, port|
      Timeout.timeout(20) do
        Net::SSH.start("localhost", "net_ssh_1", { port: port, verify_host_key: :never }.merge(options)) do |ssh|
          [ssh.transport.algorithms.host_key, ssh.exec!("echo 'foo'")]
        end
      rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        sleep 0.25
        retry
      end
    end
  end

  def test_rsa_host_key_uses_rsa_sha2_512_by_default
    assert_equal ["rsa-sha2-512", "foo\n"], connect([RSA_HOST_KEY], password: 'foopwd')
  end

  def test_ssh_rsa_only_server_is_rejected_by_default
    assert_raises(Net::SSH::Exception) do
      connect([RSA_HOST_KEY, "HostKeyAlgorithms ssh-rsa"], password: 'foopwd')
    end
  end

  def test_ssh_rsa_host_key_can_be_enabled
    assert_equal ["ssh-rsa", "foo\n"],
                 connect([RSA_HOST_KEY, "HostKeyAlgorithms ssh-rsa"], password: 'foopwd', host_key: '+ssh-rsa')
  end

  def with_rsa_key
    tmpdir do |dir|
      ssh_keygen "#{dir}/id_rsa", "rsa"
      set_authorized_key('net_ssh_1', "#{dir}/id_rsa.pub")
      yield(keys: ["#{dir}/id_rsa"], keys_only: true, auth_methods: ['publickey'], non_interactive: true)
    end
  end

  def test_ssh_rsa_only_pubkey_auth_is_rejected_by_default
    with_rsa_key do |options|
      assert_raises(Net::SSH::AuthenticationFailed) do
        connect(["PubkeyAcceptedAlgorithms ssh-rsa"], options)
      end
    end
  end

  def test_ssh_rsa_pubkey_auth_can_be_enabled
    with_rsa_key do |options|
      # OpenSSH before 9.6 lists rsa-sha2-* in server-sig-algs even when PubkeyAcceptedAlgorithms excludes them.
      _host_key, out = connect(["PubkeyAcceptedAlgorithms ssh-rsa"], options.merge(pubkey_algorithms: %w[^ssh-rsa]))
      assert_equal "foo\n", out
    end
  end
end
