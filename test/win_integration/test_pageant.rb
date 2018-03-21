require_relative '../common'
require 'net/ssh/authentication/agent'

module Authentication

  unless RUBY_PLATFORM == "java"

    class TestPageapnt < NetSSHTest
      def with_pagent
        pageant_path = 'C:\ProgramData\chocolatey\lib\putty.portable\tools\pageant.exe'
        raise "No pageant found at:#{pageant_path}" unless File.executable?(pageant_path)
        pageant_pid = Process.spawn(pageant_path)
        sleep 4
        yield
      ensure
        Process.kill(9, pageant_pid)
      end
  
      def test_agent_should_be_able_to_negotiate_with_pagent
        with_pagent do
          agent.negotiate!
        end
      end
  
      def test_agent_should_raise_without_pagent
        assert_raises Net::SSH::Authentication::AgentNotAvailable do
          agent.negotiate!
        end
      end
  
      private
  
      def agent(auto=:connect)
        @agent ||= begin
          agent = Net::SSH::Authentication::Agent.new
          agent.connect! if auto == :connect
          agent
        end
      end
    end

  end

end
