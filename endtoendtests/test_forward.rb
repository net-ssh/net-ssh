require 'common'
require 'net/ssh/buffer'
require 'net/ssh'
                      
# keyless ssh setup
#
# cat ~/.ssh/id_rsa.pub  > ~/.ssh/authorized_keys
# to test:
# ssh localhost
#

class TestForward < Test::Unit::TestCase
  
  def localhost
    'localhost'
  end
  
  def ssh_start_params
    [localhost ,ENV['USER']]
  end
  
  def find_free_port
    8080
  end
  
  def start_server_sending_lot_of_data(exceptions=nil)
    server = TCPServer.open(0)
    Thread.start do
      loop do
        Thread.start(server.accept) do |client|
          begin
            10000.times do |i| 
              client.puts "item#{i}"
            end
            client.close
          rescue 
            exceptions << $!
            raise
          end
        end
      end
    end
    return server
  end
  
  def start_server_closing_soon(exceptions=nil)
    server = TCPServer.open(0)
    Thread.start do
      loop do
        Thread.start(server.accept) do |client|
          begin
            client.recv(1024) 
            client.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
            client.close
          rescue
            exceptions <<  $!
            raise
          end
        end
      end
    end
    return server
  end
  
  def test_loop_should_not_abort_when_local_side_of_forward_is_closed
    session = Net::SSH.start(*ssh_start_params) 
    server_exc = Queue.new
    server = start_server_sending_lot_of_data(server_exc)
    remote_port = server.addr[1]
    local_port = find_free_port 
    session.forward.local(local_port, localhost, remote_port)
    client_done = Queue.new
    Thread.start do
      begin
        client = TCPSocket.new(localhost, local_port)
        client.recv(1024)
        client.close
        sleep(0.2)
      ensure
        client_done << true
      end
    end
    session.loop(0.1) { client_done.empty? }
    assert_equal "Broken pipe", "#{server_exc.pop}"
  end
  
  def test_loop_should_not_abort_when_local_side_of_forward_is_reset
    session = Net::SSH.start(*ssh_start_params)
    server_exc = Queue.new    
    server = start_server_sending_lot_of_data(server_exc)
    remote_port = server.addr[1]
    local_port = find_free_port+1
    session.forward.local(local_port, localhost, remote_port)
    client_done = Queue.new
    Thread.start do
      begin
        client = TCPSocket.new(localhost, local_port)
        client.recv(1024)
        client.setsockopt(Socket::SOL_SOCKET, Socket::SO_LINGER, [1, 0].pack("ii"))
        client.close
        sleep(0.1)
      ensure
        client_done << true
      end
    end
    session.loop(0.1) { client_done.empty? }
    assert_equal "Broken pipe", "#{server_exc.pop}"
  end
  
  def test_loop_should_not_abort_when_server_side_of_forward_is_closed
    session = Net::SSH.start(*ssh_start_params)    
    server = start_server_closing_soon
    remote_port = server.addr[1]
    local_port = find_free_port+2 
    session.forward.local(local_port, localhost, remote_port)
    client_done = Queue.new
    Thread.start do
      begin
        client = TCPSocket.new(localhost, local_port)
        1.times do |i| 
          client.puts "item#{i}"
        end
        client.close
        sleep(0.1)
      ensure                 
        client_done << true
      end
    end
    session.loop(0.1) { client_done.empty? }
  end
end