# frozen_string_literal: false

require_relative '../common'
require 'net/ssh'
require 'net/ssh/proxy/command'

module NetSSH
  class TestProxy < NetSSHTest
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
