#
# Tests for communication capability with Pageant (or KeeAgent)
# process, to include the case where it is running in different UAC
# context.
#
# To run:
# - Ensure that Pageant is running (not as administrator).
# - Open two command prompts, one as an administrator and one limited
#     (normal).
# - Within each, from the root net/ssh project directory, execute:
#       ruby -Ilib -Itest -rrubygems test/manual/test_pageant.rb
#

require_relative '../common'
require 'net/ssh/authentication/agent'

module Authentication

  class TestPageapnt < NetSSHTest
    def test_agent_should_be_able_to_negotiate
      begin
        agent.negotiate!
      rescue Net::SSH::Authentication::AgentNotAvailable
        puts "Test failing connect now!.... :#{$!}"
        sleep 1800
        raise
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
