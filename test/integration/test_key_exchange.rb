require_relative 'common'
require 'net/ssh'

class TestKeyExchange < NetSSHTest
  include IntegrationTestHelpers

  Net::SSH::Transport::Algorithms::DEFAULT_ALGORITHMS[:kex].each do |kex|
    define_method("test_kex_#{kex}") do
      skip "diffie-hellman-group14-sha1 not supported on newer sshd" if kex == "diffie-hellman-group14-sha1" && sshd_8_or_later?

      ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd', kex: kex) do |ssh|
        ssh.exec! "echo 'foo'"
      end
      assert_equal "foo\n", ret
      assert_equal 0, ret.exitstatus
    end
  end
end
