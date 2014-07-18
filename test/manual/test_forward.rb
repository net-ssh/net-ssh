#     $ ruby -Ilib -Itest -rrubygems test/manual/test_forward.rb

# Tests for the following patch:
#
#   http://github.com/net-ssh/net-ssh/tree/portfwfix
#
# It fixes 3 issues, regarding closing forwarded ports:
#
# 1.) if client closes a forwarded connection, but the server is reading, net-ssh terminates with IOError socket closed.
# 2.) if client force closes (RST) a forwarded connection, but server is reading, net-ssh terminates with
# 3.) if server closes the sending side, the on_eof is not handled.
#
# More info:
#
# http://net-ssh.lighthouseapp.com/projects/36253/tickets/7

require 'common'
require 'net/ssh/buffer'
require 'net/ssh'
require 'timeout'
require 'tempfile'

class TestForward < Test::Unit::TestCase

  def localhost
    'localhost'
  end

  def ssh_start_params
    [localhost ,ENV['USER'], {:keys => "~/.ssh/id_rsa", :verbose => :debug}]
  end

  def start_server_sending_lot_of_data(exceptions)
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

  def test_local_ephemeral_port_should_work_correctly
    session = Net::SSH.start(*ssh_start_params)

    assert_nothing_raised do
      assigned_port = session.forward.local(0, localhost, 22)
      assert_not_nil assigned_port
      assert_operator assigned_port, :>, 0
    end
  end

  def test_remote_ephemeral_port_should_work_correctly
    session = Net::SSH.start(*ssh_start_params)

    assert_nothing_raised do
      session.forward.remote(22, localhost, 0, localhost)
      session.loop { !(session.forward.active_remotes.length > 0) }
      assigned_port = session.forward.active_remotes.first[0]
      assert_not_nil assigned_port
      assert_operator assigned_port, :>, 0
    end
  end

  def test_remote_callback_should_fire
    session = Net::SSH.start(*ssh_start_params)

    assert_nothing_raised do
      got_port = nil
      session.forward.remote(22, localhost, 0, localhost) do |port|
        got_port = port
      end
      session.loop { !(session.forward.active_remotes.length > 0) }
      assert_operator session.forward.active_remote_destinations.length, :==, 1
      assert_operator session.forward.active_remote_destinations.keys.first, :==, [ 22, localhost ]
      assert_operator session.forward.active_remote_destinations.values.first, :==, [ got_port, localhost ]
      assert_operator session.forward.active_remotes.first, :==, [ got_port, localhost ]
      assigned_port = session.forward.active_remotes.first[0]
      assert_operator got_port, :==, assigned_port
      assert_not_nil assigned_port
      assert_operator assigned_port, :>, 0
    end
  end

  def test_remote_callback_should_fire_on_error_and_still_throw_exception
    session = Net::SSH.start(*ssh_start_params)

    assert_nothing_raised do
      session.forward.remote(22, localhost, 22, localhost) do |port|
        assert_operator port, :==, :error
      end
    end
    assert_raises(Net::SSH::Exception) do
      session.loop { true }
    end
  end

  def test_remote_callback_should_fire_on_error_but_not_throw_exception_if_asked_not_to
    session = Net::SSH.start(*ssh_start_params)

    assert_nothing_raised do
      got_port = nil
      session.forward.remote(22, localhost, 22, localhost) do |port|
        assert_operator port, :==, :error
        got_port = port
        :no_exception
      end
      session.loop { !got_port }
      assert_operator port, :==, :error
      assert_operator session.forward.active_remotes.length, :==, 0
    end
  end

  def test_loop_should_not_abort_when_local_side_of_forward_is_closed
    session = Net::SSH.start(*ssh_start_params)
    server_exc = Queue.new
    server = start_server_sending_lot_of_data(server_exc)
    remote_port = server.addr[1]
    local_port = 0 # request ephemeral port
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
    assert_equal "Broken pipe", "#{server_exc.pop}" unless server_exc.empty?
  end

  def test_loop_should_not_abort_when_local_side_of_forward_is_reset
    session = Net::SSH.start(*ssh_start_params)
    server_exc = Queue.new
    server = start_server_sending_lot_of_data(server_exc)
    remote_port = server.addr[1]
    local_port = 0 # request ephemeral port
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
    assert_equal "Broken pipe", "#{server_exc.pop}" unless server_exc.empty?
  end

  def create_local_socket(&blk)
    tempfile = Tempfile.new("net_ssh_forward_test")
    path = tempfile.path
    tempfile.delete
    yield UNIXServer.open(path)
    File.delete(path)
  end if defined?(UNIXServer)

  def test_forward_local_unix_socket_to_remote_port
    session = Net::SSH.start(*ssh_start_params)
    server_exc = Queue.new
    server = start_server_sending_lot_of_data(server_exc)
    remote_port = server.addr[1]
    client_data = nil

    create_local_socket do |local_socket|
      session.forward.local(local_socket, localhost, remote_port)
      client_done = Queue.new

      Thread.start do
        begin
          client = UNIXSocket.new(local_socket.path)
          client_data = client.recv(1024)
          client.close
          sleep(0.2)
        ensure
          client_done << true
        end
      end

      session.loop(0.1) { client_done.empty? }
    end

    assert_not_nil(client_data, "client should have received data")
    assert(client_data.match(/item\d/), 'client should have received the string item')
  end if defined?(UNIXSocket)

  def test_loop_should_not_abort_when_server_side_of_forward_is_closed
    session = Net::SSH.start(*ssh_start_params)
    server = start_server_closing_soon
    remote_port = server.addr[1]
    local_port = 0 # request ephemeral port
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

  def start_server
    server = TCPServer.open(0)
    Thread.start do
      loop do
        Thread.start(server.accept) do |client|
          yield(client)
        end
      end
    end
    return server
  end

  def test_server_eof_should_be_handled
    session = Net::SSH.start(*ssh_start_params)
    server = start_server do |client|
      client.write "This is a small message!"
      client.close
    end
    client_done = Queue.new
    client_exception = Queue.new
    client_data = Queue.new
    remote_port = server.addr[1]
    local_port = session.forward.local(0, localhost, remote_port)
    Thread.start do
      begin
        client = TCPSocket.new(localhost, local_port)
        data = client.read(4096)
        client.close
        client_done << data
      rescue
        client_done << $!
      end
    end
    timeout(5) do
      session.loop(0.1) { client_done.empty? }
      assert_equal "This is a small message!", client_done.pop
    end
  end
end
