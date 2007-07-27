require 'net/ssh/loggable'

module Net; module SSH; module Service

  class Forward
    include Loggable

    attr_reader :session

    Remote = Struct.new(:host, :port)

    def initialize(session)
      @session = session
      self.logger = session.logger
      @remote_forwarded_ports = {}
      @agent_forwarded = false

      session.on_open_channel('forwarded-tcpip', &method(:forwarded_tcpip))
      session.on_open_channel('auth-agent', &method(:auth_agent_channel))
      session.on_open_channel('auth-agent@openssh.com', &method(:auth_agent_channel))
    end

    def local(*args)
      if args.length < 3 || args.length > 4
        raise ArgumentError, "expected 3 or 4 parameters, got #{args.length}"
      end

      bind_address = "127.0.0.1"
      bind_address = args.shift if args.first.is_a?(String) && args.first =~ /\D/

      local_port = args.shift.to_i
      remote_host = args.shift
      remote_port = args.shift.to_i

      socket = TCPServer.new(bind_address, local_port)
      session.listen_to(socket) do |socket|
        client = socket.accept
        debug { "received connection on #{bind_address}:#{local_port}" }

        session.open_channel("direct-tcpip", :string, remote_host, :long, remote_port, :string, bind_address, :long, local_port) do |channel|
          channel.trace { "direct channel established" }
          prepare_client(client, channel, :local)
        end
      end
    end

    def remote(port, host, remote_port, remote_host="127.0.0.1")
      session.global_request("tcpip-forward", :string, remote_host, :long, remote_port) do |success, response|
        if success
          debug { "remote forward from remote #{remote_host}:#{remote_port} to #{host}:#{port} established" }
          key = "#{remote_host}:#{remote_port}"
          @remote_forwarded_ports[key] = Remote.new(host, port)
        else
          error { "remote forwarding request failed" }
          raise Net::SSH::Exception, "remote forwarding request failed"
        end
      end
    end

    # an alias, for backwards compatibility with the 1.x API
    alias :remote_to :remote

    def agent(channel)
      return if @agent_forwarded
      @agent_forwarded = true

      channel.send_channel_request("auth-agent-req@openssh.com") do |channel, success|
        if success
          @auth_agent = Authentication::Agent.new(logger)
          log { "authentication agent forwarding is active" }
        else
          channel.send_channel_request("auth-agent-req") do |channel, success|
            if success
              log { "authentication agent forwarding is active" }
            else
              error { "could not establish forwarding of authentication agent" }
            end
          end
        end
      end
    end

    private

      def prepare_client(client, channel, type)
        client.extend(Net::SSH::BufferedIo)
        client.logger = logger

        session.readers << client
        session.writers << client

        channel[:socket] = client

        channel.on_data do |ch, data|
          ch[:socket].enqueue(data)
        end

        channel.on_close do |ch|
          trace { "closing #{type} forwarded channel" }
          ch[:socket].close if !client.closed?
          session.readers.delete(ch[:socket])
          session.writers.delete(ch[:socket])
        end

        channel.on_process do |ch|
          if ch[:socket].closed?
            ch.trace { "#{type} forwarded connection closed" }
            ch.close
          elsif ch[:socket].available > 0
            data = ch[:socket].read_available(8192)
            ch.trace { "read #{data.length} bytes from client, sending over #{type} forwarded connection" }
            ch.send_data(data)
          end
        end
      end

      def forwarded_tcpip(session, channel, packet)
        connected_address  = packet.read_string
        connected_port     = packet.read_long
        originator_address = packet.read_string
        originator_port    = packet.read_long

        key = "#{connected_address}:#{connected_port}"
        remote = @remote_forwarded_ports[key]

        if remote.nil?
          raise Net::SSH::Exception, "unknown request from remote forwarded connection on #{key}"
        end

        trace { "connected #{key} originator #{originator_address}:#{originator_port}" }

        client = TCPSocket.new(remote.host, remote.port)
        prepare_client(client, channel, :remote)
      end

      def auth_agent_channel(session, channel, packet)
        trace { "opening auth-agent channel" }
        channel[:invisible] = true
        prepare_client(@auth_agent.socket, channel, :agent)
      end
  end

end; end; end