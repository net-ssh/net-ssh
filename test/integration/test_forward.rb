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

require_relative './common'
require 'net/ssh/buffer'
require 'net/ssh'
require 'net/ssh/proxy/command'
require 'timeout'
require 'tempfile'

class TestForward < Test::Unit::TestCase
  include IntegrationTestHelpers

  def localhost
    'localhost'
  end

  def user
    'net_ssh_1'
  end

  def ssh_start_params(options = {})
    [localhost ,user , {:keys => @key_id_rsa}.merge(options)]
  end

  def setup_ssh_env(&block)
    tmpdir do |dir|
      @key_id_rsa = "#{dir}/id_rsa"
      sh "rm -rf #{@key_id_rsa} #{@key_id_rsa}.pub"
      sh "ssh-keygen -f #{@key_id_rsa} -t rsa -N ''"
      set_authorized_key(user,"#{@key_id_rsa}.pub")
      yield
    end
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

  def test_in_file_no_password
    setup_ssh_env do
      ret = Net::SSH.start(*ssh_start_params) do |ssh|
      #ret = Net::SSH.start("localhost", "net_ssh_1", {keys: @key_id_rsa}) do |ssh|
        ssh.exec! 'echo "hello from:$USER"'
      end
      assert_equal "hello from:net_ssh_1\n", ret
    end
  end

  def test_local_ephemeral_port_should_work_correctly
    setup_ssh_env do
      session = Net::SSH.start(*ssh_start_params)

      assert_nothing_raised do
        assigned_port = session.forward.local(0, localhost, 22)
        assert_not_nil assigned_port
        assert_operator assigned_port, :>, 0
      end
    end
  end

  def test_remote_ephemeral_port_should_work_correctly
    setup_ssh_env do
      session = Net::SSH.start(*ssh_start_params)

      assert_nothing_raised do
        session.forward.remote(22, localhost, 0, localhost)
        session.loop { !(session.forward.active_remotes.length > 0) }
        assigned_port = session.forward.active_remotes.first[0]
        assert_not_nil assigned_port
        assert_operator assigned_port, :>, 0
      end
    end
  end

  def test_remote_callback_should_fire
    setup_ssh_env do
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
  end

  def test_remote_callback_should_fire_on_error_and_still_throw_exception
    setup_ssh_env do
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
  end

  def test_remote_callback_should_fire_on_error_but_not_throw_exception_if_asked_not_to
    setup_ssh_env do
      session = Net::SSH.start(*ssh_start_params)

      assert_nothing_raised do
        got_port = nil
        session.forward.remote(22, localhost, 22, localhost) do |port|
          assert_operator port, :==, :error
          got_port = port
          :no_exception
        end
        session.loop { !got_port }
        assert_operator got_port, :==, :error
        assert_operator session.forward.active_remotes.length, :==, 0
      end
    end
  end

  def test_loop_should_not_abort_when_local_side_of_forward_is_closed
    setup_ssh_env do
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
  end

  def test_loop_should_not_abort_when_local_side_of_forward_is_reset
    setup_ssh_env do
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
  end

  def create_local_socket(&blk)
    tempfile = Tempfile.new("net_ssh_forward_test")
    path = tempfile.path
    tempfile.delete
    yield UNIXServer.open(path)
    File.delete(path)
  end if defined?(UNIXServer)

  def test_forward_local_unix_socket_to_remote_port
    setup_ssh_env do
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
    end
  end if defined?(UNIXSocket)

  def test_loop_should_not_abort_when_server_side_of_forward_is_closed
    setup_ssh_env do
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
  end

  def start_server(server = nil, &block)
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

  def test_client_close_should_be_handled_remote
    setup_ssh_env do
      message = "This is a small message!"*1000
      session = Net::SSH.start(*ssh_start_params)
      server_done = Queue.new
      server = start_server do |client|
        begin
          data = client.read message.size
          server_done << data
          client.close
        rescue
          server_done << $!
        end
      end
      client_done = Queue.new
      got_remote_port = Queue.new
      local_port = server.addr[1]
      session.forward.remote(0, localhost, local_port) do |actual_remote_port|
        got_remote_port << actual_remote_port
      end
      session.loop(0.1) { got_remote_port.empty? }
      remote_port = got_remote_port.pop
      Thread.start do
        begin
          client = TCPSocket.new(localhost, remote_port)
          client.write(message)
          client.close
          client_done << true
        rescue
          client_done << $!
        end
      end
      timeout(5) do
        session.loop(0.1) { server_done.empty? }
        assert_equal message, server_done.pop
      end
    end
  end

  class TCPProxy
    def initialize()
      @sockets = []
    end
    attr_reader :sockets

    def open(host, port, connection_options = nil)
      socket = TCPSocket.new(host,port)
      @sockets << socket
      socket
    end

    def close_all
      sockets.each do |socket|
        socket.close
      end
    end
  end

  def test_transport_close_should_closes_channels_with_tcps
    setup_ssh_env do
      server = start_server do |client|
        client.puts "Hello"
        sleep(100)
        client.puts "Hallo"
      end
      proxy = TCPProxy.new()
      session = Net::SSH.start(*ssh_start_params(proxy: proxy))
      remote_port = server.addr[1]
      local_port = session.forward.local(0, localhost, remote_port)

      # read on forwarded port
      client_done = Queue.new
      Thread.start do
        begin
          client = TCPSocket.new(localhost, local_port)
          client.read(6)
          proxy.close_all
          client.read(7)
          client.close
          client_done << true
        rescue
          client_done << $!
        end
      end
      Timeout.timeout(5) do
        begin
          session.loop(0.1) { true }
        rescue EOFError, IOError
          #puts "Error: #{$!} #{$!.backtrace.join("\n")}"
        end
      end
      begin
        Timeout.timeout(5) do
          assert_equal true, client_done.pop
        end
      rescue
        puts "Server error: #{server_error.class} #{server_error} bt:#{server_error.backtrace.join("\n")}"
        raise
      end
    end
  end

  def todo_test_transport_close_should_closes_channels_with_proxy
    setup_ssh_env do
      server = start_server do |client|
        client.puts "Hello"
        sleep(100)
        client.puts "Hallo"
      end
      proxy = Net::SSH::Proxy::Command.new("/bin/nc localhost 22")
      session = Net::SSH.start(*ssh_start_params(proxy: proxy))
      remote_port = server.addr[1]
      local_port = session.forward.local(0, localhost, remote_port)

      # read on forwarded port
      client_done = Queue.new
      Thread.start do
        begin
          client = TCPSocket.new(localhost, local_port)
          client.read(6)
          system("killall /bin/nc")
          client.read(7)
          client.close
          client_done << true
        rescue
          client_done << $!
        end
      end
      Timeout.timeout(5) do
        begin
          session.loop(0.1) { true }
        rescue EOFError
          begin
            session.close
          rescue
          end
          #puts "Error: #{$!} #{$!.backtrace.join("\n")}"
        end
        assert_equal true, client_done.pop
      end
    end
  end

  def test_client_close_should_be_handled
    setup_ssh_env do
      message = "This is a small message!"*1000
      session = Net::SSH.start(*ssh_start_params)
      server_done = Queue.new
      server = start_server do |client|
        begin
          data = client.read message.size
          server_done << data
          client.close
        rescue
          server_done << $!
        end
      end
      client_done = Queue.new
      remote_port = server.addr[1]
      local_port = session.forward.local(0, localhost, remote_port)
      Thread.start do
        begin
          client = TCPSocket.new(localhost, local_port)
          client.write(message)
          client.close
          client_done << true
        rescue
          client_done << $!
        end
      end
      timeout(5) do
        session.loop(0.1) { server_done.empty? }
        assert_equal message, server_done.pop
      end
    end
  end

  def test_server_eof_should_be_handled_remote
    setup_ssh_env do
      message = "This is a small message!"
      session = Net::SSH.start(*ssh_start_params)
      server = start_server do |client|
        client.write message
        client.close
      end
      client_done = Queue.new
      got_remote_port = Queue.new
      local_port = server.addr[1]
      session.forward.remote(0, localhost, local_port) do |actual_remote_port|
        got_remote_port << actual_remote_port
      end
      session.loop(0.1) { got_remote_port.empty? }
      remote_port = got_remote_port.pop
      Thread.start do
        begin
          client = TCPSocket.new(localhost, remote_port)
          data = client.read(4096)
          client.close
          client_done << data
        rescue
          client_done << $!
        end
      end
      timeout(5) do
        session.loop(0.1) { client_done.empty? }
        assert_equal message, client_done.pop
      end
    end
  end

  def test_server_eof_should_be_handled
    setup_ssh_env do
      message = "This is a small message!"
      session = Net::SSH.start(*ssh_start_params)
      server = start_server do |client|
        client.write message
        client.close
      end
      client_done = Queue.new
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
        assert_equal message, client_done.pop
      end
    end
  end

  def _run_reading_client(client_done, local_port)
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
  end

  def test_cannot_open_connection_should_allow_further_connections_on_different_forward
    setup_ssh_env do
      session = Net::SSH.start(*ssh_start_params)
      server = start_server do |client|
        data = client.write "hello"
        client.close
      end
      # Forward to a non existing port
      non_existing_port = 1234
      local_port = session.forward.local(0, localhost, non_existing_port)
      # should return connection refused
      client_done = Queue.new
      _run_reading_client(client_done, local_port)
      timeout(5) do
        session.loop(0.1) { client_done.empty? }
      end
      assert_equal nil, client_done.pop
      assert client_done.empty?
      # Forward to existing port
      remote_port = server.addr[1]
      local_port = session.forward.local(0, localhost, remote_port)
      _run_reading_client(client_done, local_port)
      timeout(5) do
        session.loop(0.1) { client_done.empty? }
      end
      assert_equal "hello", client_done.pop
      assert client_done.empty?
    end
  end

  def test_cannot_open_connection_should_allow_further_connections_on_same
    setup_ssh_env do
      session = Net::SSH.start(*ssh_start_params)
      server = TCPServer.open(0)
      # Forward to a non existing port
      remote_port = server.addr[1]
      server.close
      local_port = session.forward.local(0, localhost, remote_port)
      # should return connection refused
      client_done = Queue.new
      _run_reading_client(client_done, local_port)
      timeout(5) do
        session.loop(0.1) { client_done.empty? }
      end
      assert_equal nil, client_done.pop
      assert client_done.empty?
      # start server
      server = TCPServer.open(remote_port)
      server = start_server(server) do |client|
        data = client.write "hello"
        client.close
      end
      _run_reading_client(client_done, local_port)
      timeout(5) do
        session.loop(0.1) { client_done.empty? }
      end
      assert_equal "hello", client_done.pop
      assert client_done.empty?
    end
  end

  def test_cancel_local
    setup_ssh_env do
      session = Net::SSH.start(*ssh_start_params)
      server = start_server(server) do |client|
        data = client.write "hello"
        client.close
      end
      remote_port = server.addr[1]
      local_port = session.forward.local(0, localhost, remote_port)
      # run client
      client_done = Queue.new
      _run_reading_client(client_done, local_port)
      timeout(5) do
        session.loop(0.1) { client_done.empty? }
      end
      assert_equal "hello", client_done.pop
      # cancel
      session.forward.cancel_local(local_port)
      session.loop(0.1)
      assert_equal({}, session.channels)
    end
  end
end
