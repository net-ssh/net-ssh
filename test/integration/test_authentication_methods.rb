# frozen_string_literal: true

require_relative 'common'
require 'fileutils'
require 'tmpdir'

require 'net/ssh'

require 'timeout'

class TestAuthenticationMethods < NetSSHTest
  include IntegrationTestHelpers

  # net-ssh prefers publickey, but this sshd only accepts it after password
  def test_password_then_publickey
    tmpdir do |dir|
      ssh_keygen "#{dir}/id_rsa", "rsa"
      set_authorized_key('net_ssh_1', "#{dir}/id_rsa.pub")

      # sshd uses the first value it reads for a keyword
      config_lines = ["AuthenticationMethods password,publickey"] + File.read('/etc/ssh/sshd_config').split("\n")

      Tempfile.open('empty_kh') do |f|
        f.close
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(4) do
            ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd', keys: ["#{dir}/id_rsa"], non_interactive: true,
                                                           port: port, user_known_hosts_file: [f.path]) do |ssh|
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
end
