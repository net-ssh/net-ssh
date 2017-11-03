require_relative 'common'
require 'net/ssh'

class TestPassword < NetSSHTest
  include IntegrationTestHelpers

  def test_with_password_parameter
    ret = Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd') do |ssh|
      ssh.exec! 'echo "hello from:$USER"'
    end
    assert_equal ret, "hello from:net_ssh_1\n"
  end

  def test_keyboard_interactive_with_good_password
    ps = Object.new
    pt = Object.new
    pt.expects(:start).with(type: 'keyboard-interactive', name: '', instruction: '').returns(ps)
    ps.expects(:ask).with('Password: ', false).returns("foopwd")
    ps.expects(:success)
    ret = Net::SSH.start("localhost", "net_ssh_1", auth_methods: ['keyboard-interactive'], password_prompt: pt) do |ssh|
      ssh.exec! 'echo "hello from:$USER"'
    end
    assert_equal ret, "hello from:net_ssh_1\n"
  end

  def test_keyboard_interactive_with_one_failed_attempt
    ps = Object.new
    pt = Object.new
    pt.expects(:start).with(type: 'keyboard-interactive', name: '', instruction: '').returns(ps)
    ps.expects(:ask).twice.with('Password: ', false).returns("badpwd").then.with('Password: ', false).returns("foopwd")
    ps.expects(:success)
    ret = Net::SSH.start("localhost", "net_ssh_1", auth_methods: ['keyboard-interactive'], password_prompt: pt) do |ssh|
      ssh.exec! 'echo "hello from:$USER"'
    end
    assert_equal ret, "hello from:net_ssh_1\n"
  end

  def test_password_with_good_password
    ps = Object.new
    pt = Object.new
    pt.expects(:start).with(type: 'password', user: 'net_ssh_1', host: 'localhost').returns(ps)
    ps.expects(:ask).with("net_ssh_1@localhost's password:", false).returns("foopwd")
    ps.expects(:success)

    ret = Net::SSH.start("localhost", "net_ssh_1", auth_methods: ['password'], password_prompt: pt) do |ssh|
      ssh.exec! 'echo "hello from:$USER"'
    end
    assert_equal ret, "hello from:net_ssh_1\n"
  end

  def test_bad_password_should_throw_auth_invalid
    assert_raises Net::SSH::AuthenticationFailed do
      Net::SSH.start("localhost", "net_ssh_1", password: "wrong_password", auth_methods: ['password'], non_interactive: true) do |ssh|
        ssh.exec! 'echo "hello from:$USER"'
      end
    end
  end
end
