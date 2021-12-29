require_relative 'common'
require 'fileutils'
require 'tmpdir'

require 'net/ssh'

require 'timeout'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
# and usually connecting to net_ssh_2 user password foo2pwd
class TestGcmCipher < NetSSHTest
  include IntegrationTestHelpers

  def run_with_only_cipher(cipher)
    config_lines = File.read('/etc/ssh/sshd_config').split("\n")
    config_lines = config_lines.map do |line|
      if line =~ /^Ciphers/
        "##{line}"
      else
        line
      end
    end
    config_lines.push("Ciphers #{cipher}")

    Tempfile.open('empty_kh') do |f|
      f.close
      start_sshd_7_or_later(config: config_lines, debug: true) do |_pid, port|
        Timeout.timeout(4) do
          # We have our own sshd, give it a chance to come up before
          # listening.
          ret = Net::SSH.start("localhost", "net_ssh_1", encryption: cipher, password: 'foopwd', port: port, user_known_hosts_file: [f.path], verbose: :debug) do |ssh|
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

  def test_aes128_gcm
    run_with_only_cipher('aes128-gcm@openssh.com')
  end

  def test_aes256_gcm
    run_with_only_cipher('aes256-gcm@openssh.com')
  end
end