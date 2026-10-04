require_relative '../common'
require 'net/ssh/authentication/agent'
require 'net/ssh/service/forward'

module Service
  class TestForward < NetSSHTest
    def test_auth_agent_channel_should_connect_to_identity_agent
      session = stub("session", logger: nil, options: { identity_agent: "/tmp/agent.sock" }, on_open_channel: nil)
      forward = Net::SSH::Service::Forward.new(session)
      agent_socket = stub("agent_socket")

      Net::SSH::Authentication::Agent.expects(:connect).with(nil, nil, "/tmp/agent.sock").returns(stub("agent", socket: agent_socket))
      forward.expects(:prepare_simple_client).with(agent_socket, anything, :agent)

      forward.send(:auth_agent_channel, session, {}, nil)
    end
  end
end
