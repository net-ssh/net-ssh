require_relative '../common'
require 'net/ssh'

class TestPageapnt < NetSSHTest
  def test_connect
    ret = Net::SSH.start("localhost", "foo", password: 'foo', port: '2223') do |ssh|
      ssh.exec! "cmd /c echo hello from windows!"
    end
    assert_equal "hello from windows!\r\n", ret
  end
end
