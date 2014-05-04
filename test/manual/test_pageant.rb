#     $ ruby -Ilib -Itest -rrubygems test/manual/test_pageant.rb

#
# Tests for communication capability with Pageant process running in
# different UAC context.
# 
# Test prerequisite:
# - Pageant process running on machine in different UAC context from
#   the command prompt running the test.
#

require 'common'
require 'net/ssh/authentication/agent'

module Authentication

  class TestPageant < Test::Unit::TestCase

    def test_agent_should_be_able_to_negotiate
      assert_nothing_raised(Net::SSH::Authentication::AgentNotAvailable) { agent.negotiate! }
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