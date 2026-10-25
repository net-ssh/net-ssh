require_relative 'common'
require 'stringio'
require 'tmpdir'
require 'timeout'
require 'net/ssh'

# see Vagrantfile,playbook for env.
class TestServerSigAlgs < NetSSHTest
  include IntegrationTestHelpers

  def connect(config_lines, options = {})
    log = StringIO.new
    logger = Logger.new(log)
    logger.level = Logger::DEBUG
    start_sshd_7_or_later(config: config_lines) do |_pid, port|
      Timeout.timeout(20) do
        out = Net::SSH.start("localhost", "net_ssh_1", { port: port, verify_host_key: :never, logger: logger }.merge(options)) do |ssh|
          ssh.exec!("echo 'foo'")
        end
        [out, log.string.scan(/trying publickey \(\S+\) alg (\S+)/).flatten]
      rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
        sleep 0.25
        retry
      end
    end
  end

  def with_keys(refused_rsa_keys)
    tmpdir do |dir|
      refused = Array.new(refused_rsa_keys) { |i| "#{dir}/id_rsa#{i}" }
      refused.each { |key| ssh_keygen(key, "rsa") }
      ssh_keygen "#{dir}/id_ecdsa", "ecdsa"
      set_authorized_key('net_ssh_1', "#{dir}/id_ecdsa.pub")
      yield(keys: refused + ["#{dir}/id_ecdsa"], keys_only: true, auth_methods: ['publickey'], non_interactive: true)
    end
  end

  def test_refused_rsa_keys_are_offered_once_each
    with_keys(3) do |options|
      out, offered = connect(["MaxAuthTries 6"], options)
      assert_equal "foo\n", out
      assert_equal %w[rsa-sha2-512 rsa-sha2-512 rsa-sha2-512 ecdsa-sha2-nistp256], offered
    end
  end

  def test_rsa_signature_algorithm_follows_pubkey_algorithms_order
    with_keys(1) do |options|
      out, offered = connect(["MaxAuthTries 6"], options.merge(pubkey_algorithms: %w[rsa-sha2-256 rsa-sha2-512 ecdsa-sha2-nistp256]))
      assert_equal "foo\n", out
      assert_equal %w[rsa-sha2-256 ecdsa-sha2-nistp256], offered
    end
  end
end
