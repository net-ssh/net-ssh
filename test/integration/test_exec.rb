require_relative 'common'
require 'net/ssh'

class TestExec < NetSSHTest
  include IntegrationTestHelpers

  def test_error_exitstatus
    ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd') do |ssh|
      ssh.exec! "exit 42"
    end
    assert_equal "", ret
    assert_equal 42, ret.exitstatus
  end

  def test_ok_exitstatus
    ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd') do |ssh|
      ssh.exec! "echo 'foo'"
    end
    assert_equal "foo\n", ret
    assert_equal 0, ret.exitstatus
  end
end
