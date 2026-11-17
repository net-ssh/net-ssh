require_relative 'common'
require 'fileutils'
require 'tmpdir'

require 'net/ssh'

require 'timeout'

class TestMLKEM768X25519Sha256 < NetSSHTest
  include IntegrationTestHelpers

  KEX = "mlkem768x25519-sha256"

  def setup
    skip "ML-KEM-768/X25519 is not available" unless Net::SSH::Transport::Kex::MLKEM768X25519Sha256Loader::LOADED
    skip "#{KEX} is not supported by this OpenSSH" unless openssh_kex_supported?(KEX)
  end

  def test_with_only_mlkem768x25519_kex
    config_lines = File.read('/etc/ssh/sshd_config').split("\n")
    config_lines = config_lines.map do |line|
      if line =~ /^KexAlgorithms/
        "##{line}"
      else
        line
      end
    end
    config_lines.push("KexAlgorithms #{KEX}")

    Tempfile.open('empty_kh') do |f|
      f.close
      start_sshd_7_or_later(config: config_lines) do |_pid, port|
        Timeout.timeout(4) do
          ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd', port: port, user_known_hosts_file: [f.path]) do |ssh|
            assert_equal KEX, ssh.transport.algorithms.kex
            ssh.exec! "echo 'foo'"
          end
          assert_equal "foo\n", ret
        rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
          sleep 0.25
          retry
        end
      end
    end
  end

  private

  def openssh_kex_supported?(name)
    `ssh -Q kex 2>/dev/null`.split.include?(name)
  end
end
