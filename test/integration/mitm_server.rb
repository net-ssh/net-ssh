# Simple Man in the middle server
#
# server = MitmServer.new('localhost', 22)
# Net.SSH.start('localhost', ENV['USER'], port: server.port)
# server.run

class MitmServer < TCPServer
  attr_accessor :local_read_size
  attr_accessor :target_read_size

  def initialize(remote_host = 'localhost', remote_port = 22)
    @remote_host = remote_host
    @remote_port = remote_port
    @server = TCPServer.open(0)
    @local_read_size = 2048
    @target_read_size = 2048
  end

  def port
    @server.addr[1]
  end

  def host
    'localhost'
  end

  def run
    start(@server, @remote_host, @remote_port)
  end

  private

  def start_server(server, &block)
    server ||= TCPServer.open(0)
    Thread.start do
      loop do
        Thread.start(server.accept) do |client|
          yield(client)
        end
      end
    end
    return server
  end

  def dlog(message); end

  def start(server, remote_host, remote_port)
    err = nil
    server = start_server(server) do |local|
      remote = TCPSocket.new(remote_host, remote_port)
      loop do
        r,_w,_e = IO.select([local, remote],nil,nil)
        if r.include? local
          begin
            data = local.recv local_read_size 
          rescue StandardError => e
            data = nil
            dlog "Local closed: #{e}"
            break
          end
          if data.empty?
            dlog "Local closed: #{data.inspect}"
            break
          end
          dlog "Forwarding: #{data.length} to remote"
          begin
            remote.write data
          rescue StandardError => e
            dlog "remote closed: #{e}"
            break
          end
        end
        if r.include? remote # rubocop:disable Style/Next
          begin
            data = remote.recv target_read_size
          rescue StandardError => e
            dlog "remote closed: #{e}"
            break
          end
          if data.nil? || data.empty?
            dlog "Remote closed: #{data.inspect} #{err.inspect}"
            break
          end
          dlog "Forwarding: #{data.length} to local"
          begin
            local.write data
          rescue StandardError => e
            dlog "local closed: #{e}"
            break
          end
        end
      end

      dlog "Closing..."
      local.close
      remote.close
    end
    @server = server
    return server
  end
end
