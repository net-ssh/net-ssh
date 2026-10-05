require_relative '../common'
require 'net/ssh'
require 'net/ssh/proxy/command'

module NetSSH
  class TestProxy < NetSSHTest
    def test_open_should_reject_shell_metacharacters_in_substituted_values
      proxy = Net::SSH::Proxy::Command.new('nc -l %r %h %p')
      IO.expects(:popen).never

      ["x$(id)", "x;id", "x`id`", "x id", "-oProxyCommand=id"].each do |host|
        assert_raises(ArgumentError) { proxy.open(host, 22, remote_user: "user") }
      end
      ["u$(id)", "u;id", "-oProxyCommand=id", "u -x", "u\\"].each do |user|
        assert_raises(ArgumentError) { proxy.open("example.com", 22, remote_user: user) }
      end
      assert_raises(ArgumentError) { proxy.open("example.com", "22$(id)", remote_user: "user") }
    end

    def test_open_should_substitute_ordinary_values_unchanged
      proxy = Net::SSH::Proxy::Command.new('nc -l %r %h %p')
      IO.expects(:popen).with("nc -l first.last example.com 2222", "r+").raises(Errno::ENOENT)
      IO.expects(:popen).with("nc -l user fe80::1%en0 22", "r+").raises(Errno::ENOENT)

      assert_raises(Net::SSH::Proxy::ConnectError) { proxy.open("example.com", 2222, remote_user: "first.last") }
      assert_raises(Net::SSH::Proxy::ConnectError) { proxy.open("fe80::1%en0", 22, remote_user: "user") }
    end

    unless Gem.win_platform?
      def test_process_is_stopped_on_timeout
        10.times do
          Process.waitpid(0, Process::WNOHANG) rescue true # rubocop:disable Style/RescueModifier
        end

        proxy = Net::SSH::Proxy::Command.new('sleep 10')
        proxy.timeout = 2
        host = 'foo'
        port = 1
        assert_raises Net::SSH::Proxy::ConnectError do
          proxy.open(host, port)
        end
        sleep 0.2
        assert_raises Errno::ECHILD do
          Process.waitpid(0, Process::WNOHANG)
          skip "This test is fragile TODO revise"
        end
      end
    end
  end
end
