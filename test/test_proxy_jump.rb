require_relative 'common'
require 'net/ssh/proxy/jump'

class TestProxyJump < NetSSHTest
  def test_is_a_proxy_command
    proxy = Net::SSH::Proxy::Jump.new("user@jumphost")
    assert proxy.is_a?(Net::SSH::Proxy::Command)
  end

  def test_host
    proxy = Net::SSH::Proxy::Jump.new("jumphost")
    proxy.build_proxy_command_equivalent
    assert_equal "ssh -W %h:%p jumphost", proxy.command_line_template
  end

  def test_user_host
    proxy = Net::SSH::Proxy::Jump.new("sally@proxy")
    proxy.build_proxy_command_equivalent
    assert_equal "ssh -l sally -W %h:%p proxy", proxy.command_line_template
  end

  def test_user_host_port
    proxy = Net::SSH::Proxy::Jump.new("bob@jump:2222")
    proxy.build_proxy_command_equivalent
    assert_equal "ssh -l bob -p 2222 -W %h:%p jump", proxy.command_line_template
  end

  def test_multiple_jump_proxies
    proxy = Net::SSH::Proxy::Jump.new("user1@proxy1,user2@proxy2,user3@proxy3")
    proxy.build_proxy_command_equivalent
    assert_equal "ssh -l user1 -J user2@proxy2,user3@proxy3 -W %h:%p proxy1", proxy.command_line_template
  end

  def test_config_override
    proxy = Net::SSH::Proxy::Jump.new("proxy")
    proxy.build_proxy_command_equivalent(config: "/home/user/.ssh/config2")
    assert_equal "ssh -F /home/user/.ssh/config2 -W %h:%p proxy", proxy.command_line_template
  end

  def test_config_false
    proxy = Net::SSH::Proxy::Jump.new("proxy")
    proxy.build_proxy_command_equivalent(config: false)
    assert_equal "ssh -W %h:%p proxy", proxy.command_line_template
  end

  def test_config_true
    proxy = Net::SSH::Proxy::Jump.new("proxy")
    proxy.build_proxy_command_equivalent(config: true)
    assert_equal "ssh -W %h:%p proxy", proxy.command_line_template
  end
end
