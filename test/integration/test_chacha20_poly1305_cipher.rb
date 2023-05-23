require_relative 'common'
require 'fileutils'
require 'tmpdir'

require 'net/ssh'

require 'timeout'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
# and usually connecting to net_ssh_2 user password foo2pwd
class TestChacha20Poly1305Cipher < NetSSHTest
  include IntegrationTestHelpers

  def test_with_only_chacha20_cipher
    config_lines = File.read('/etc/ssh/sshd_config').split("\n")
    config_lines = config_lines.map do |line|
      if line =~ /^Ciphers/
        "##{line}"
      else
        line
      end
    end
    config_lines.push("Ciphers chacha20-poly1305@openssh.com")

    Tempfile.open('empty_kh') do |f|
      f.close
      start_sshd_7_or_later(config: config_lines, debug: true) do |_pid, port|
        Timeout.timeout(4) do
          # We have our own sshd, give it a chance to come up before
          # listening.
          ret = Net::SSH.start("localhost", "net_ssh_1", encryption: "chacha20-poly1305@openssh.com", password: 'foopwd', port: port, user_known_hosts_file: [f.path], verbose: :debug) do |ssh|
            #assert_equal ssh.transport.algorithms.kex, "curve25519-sha256"
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
end
