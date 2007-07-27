require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/transport/server_version'

module Net; module SSH; module Authentication

  # A trivial exception class for representing agent-specific errors.
  class AgentError < Net::SSH::Exception; end

  class AgentNotAvailable < AgentError; end

  # This class implements a simple client for the ssh-agent protocol. It
  # does not implement any specific protocol, but instead copies the
  # behavior of the ssh-agent functions in the OpenSSH library (3.8).
  #
  # This means that although it behaves like a SSH1 client, it also has
  # some SSH2 functionality (like signing data).
  class Agent
    include Loggable

    module Comment
      attr_accessor :comment
    end

    SSH2_AGENT_REQUEST_VERSION    = 1
    SSH2_AGENT_REQUEST_IDENTITIES = 11
    SSH2_AGENT_IDENTITIES_ANSWER  = 12
    SSH2_AGENT_SIGN_REQUEST       = 13
    SSH2_AGENT_SIGN_RESPONSE      = 14
    SSH2_AGENT_FAILURE            = 30
    SSH2_AGENT_VERSION_RESPONSE   = 103

    SSH_COM_AGENT2_FAILURE        = 102

    SSH_AGENT_REQUEST_RSA_IDENTITIES = 1
    SSH_AGENT_RSA_IDENTITIES_ANSWER  = 2
    SSH_AGENT_FAILURE                = 5

    attr_reader :socket

    def initialize(logger=nil)
      self.logger = logger
      connect!
    end

    # Connect to the agent process using the socket factory and socket name
    # given by the attribute writers. If the agent on the other end of the
    # socket reports that it is an SSH2-compatible agent, this will fail
    # (it only supports the ssh-agent distributed by OpenSSH).
    def connect!
      begin
        trace { "connecting to ssh-agent" }
        @socket = UNIXSocket.open(ENV['SSH_AUTH_SOCK'])
      rescue
        error { "could not connect to ssh-agent" }
        raise AgentNotAvailable
      end

      # determine what type of agent we're communicating with
      buffer = Buffer.from(:string, Transport::ServerVersion::PROTO_VERSION)
      type, body = send_with_reply(SSH2_AGENT_REQUEST_VERSION, buffer)

      if type == SSH2_AGENT_VERSION_RESPONSE
        raise NotImplementedError, "SSH2 agents are not yet supported"
      elsif type != SSH_AGENT_RSA_IDENTITIES_ANSWER
        raise AgentError, "unknown response from agent: #{type}, #{body.to_s.inspect}"
      end
    end

    # Return an array of all identities (public keys) known to the agent.
    # Each key returned is augmented with a +comment+ property which is set
    # to the comment returned by the agent for that key.
    def identities
      type, body = send_with_reply(SSH2_AGENT_REQUEST_IDENTITIES)
      raise AgentError, "could not get identity count" if agent_failed(type)
      raise AgentError, "bad authentication reply: #{type}" if type != SSH2_AGENT_IDENTITIES_ANSWER

      identities = []
      body.read_long.times do
        key = Buffer.new(body.read_string).read_key
        key.extend(Comment)
        key.comment = body.read_string
        identities.push key
      end

      return identities
    end

    # Closes this socket. This agent reference is no longer able to
    # query the agent.
    def close
      @socket.close
    end

    # Using the agent and the given public key, sign the given data. The
    # signature is returned in SSH2 format.
    def sign(key, data)
      blob = Buffer.from(:key, key)

      packet_data = Buffer.from(:string, blob.to_s, :string, data.to_s, :long, 0)
      type, reply = send_with_reply(SSH2_AGENT_SIGN_REQUEST, packet_data)

      if agent_failed(type)
        raise AgentError, "agent could not sign data with requested identity"
      elsif type != SSH2_AGENT_SIGN_RESPONSE
        raise AgentError, "bad authentication response #{type}"
      end

      return reply.read_string
    end

    # Send a new packet of the given type, with the associated data.
    def send_packet(type, data=nil)
      buffer = Buffer.from(:long, (data ? data.length : 0) + 1, :byte, type.to_i)
      buffer.write(data.to_s) if data
      trace { "sending agent request #{type} len #{buffer.to_s.length}" }
      @socket.send buffer.to_s, 0
    end
    private :send_packet

    # Read the next packet from the agent. This will return a two-part
    # tuple consisting of the packet type, and the packet's body (which
    # is returned as a Net::SSH::Buffer).
    def read_packet
      length = @socket.read(4).unpack("N").first - 1
      type = @socket.read(1).unpack("C").first
      reader = Net::SSH::Buffer.new(@socket.read(length))
      trace { "received agent packet #{type} len #{length}" }
      return type, reader
    end
    private :read_packet

    # Send the given packet and return the subsequent reply from the agent.
    # (See #send_packet and #read_packet).
    def send_with_reply(type, data=nil)
      send_packet(type, data)
      read_packet
    end
    private :send_with_reply

    # Returns +true+ if the parameter indicates a "failure" response from
    # the agent, and +false+ otherwise.
    def agent_failed(type)
      type == SSH_AGENT_FAILURE ||
      type == SSH2_AGENT_FAILURE ||
      type == SSH_COM_AGENT2_FAILURE
    end
    private :agent_failed

  end

end; end; end