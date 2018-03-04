require_relative '../common'
require 'net/ssh'
require 'net/ssh/proxy/command'

module NetSSH
  class TestProxy < NetSSHTest
    unless Gem.win_platform?
      def test_process_is_stopped_on_timeout
        proxy = Net::SSH::Proxy::Command.new('sleep 10')
        proxy.timeout = 2
        host = 'foo'
        port = 1
        assert_raises Net::SSH::Proxy::ConnectError do
          proxy.open(host, port)
        end
        sleep 0.1
        assert_raises Errno::ECHILD do
          Process.waitpid(0, Process::WNOHANG)
        end
      end
    end
  end
end
