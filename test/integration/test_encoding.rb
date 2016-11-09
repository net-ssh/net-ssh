require_relative 'common'
require 'fileutils'
require 'tmpdir'

require 'net/ssh'

class TestEncoding < NetSSHTest
  def test_unicode_character
    ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd') do |ssh|
      ssh.exec! "echo \"hello from:$USER\" \u2603"
    end
    assert_equal ret, "hello from:net_ssh_1 \u2603\n"
  end

  def test_long_command_with_unicode_in_it
    string = "eeeeeeeeeeeeeeeeeeeeeeeeeewwowowowìeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    command = "echo \"#{string}\""
    ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd') do |ssh|
      ssh.exec! command
    end
    assert_equal ret, "#{string}\n"
  end
end