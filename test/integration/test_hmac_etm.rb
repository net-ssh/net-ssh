require_relative 'common'
require 'fileutils'
require 'tmpdir'

require 'net/ssh'

require 'timeout'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
# and usually connecting to net_ssh_2 user password foo2pwd
class TestHMacEtm < NetSSHTest
  include IntegrationTestHelpers

  variants = {
    etm256: "hmac-sha2-256-etm@openssh.com",
    etm512: "hmac-sha2-512-etm@openssh.com"
  }

  def config_with_macs(macs)
    config_lines = File.read('/etc/ssh/sshd_config').split("\n")
    config_lines = config_lines.map do |line|
      if line =~ /^MACs/
        "##{line}"
      else
        line
      end
    end
    config_lines.push("MACs #{macs}")
  end

  variants.each do |key,variant|
    define_method "test_with_only_hmac_etm#{key}" do
      start_sshd_7_or_later(config: config_with_macs(variant)) do |_pid, port|
        Timeout.timeout(4) do
          begin
            # We have our own sshd, give it a chance to come up before
            # listening.
            ret = Net::SSH.start(
              "localhost",
              "net_ssh_1",
              password: 'foopwd',
              port: port,
              hmac: [variant]
            ) do |ssh|
              assert_equal ssh.transport.algorithms.hmac_client, variant
              assert_equal ssh.transport.algorithms.hmac_server, variant
              ssh.exec! "echo 'foo123'"
            end
            assert_equal "foo123\n", ret
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end
end