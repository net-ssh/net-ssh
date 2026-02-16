require_relative 'common'
require 'net/ssh'

class TestHandshakeTimeout < NetSSHTest
  include IntegrationTestHelpers

  def with_non_responding_server(input = nil, &block)
    port = "4444"
    pipe = IO.popen("/bin/nc -l -k -p #{port}", "w", out: "/dev/null")
    begin
      pipe << input if input
      yield(port)
    ensure
      Process.kill("TERM", pipe.pid)
    end
  end

  def nc_port_open?(port)
    Socket.tcp("localhost", port, connect_timeout: 1) { true } rescue false # rubocop:disable Style/RescueModifier
  end

  def test_error_exitstatus
    with_non_responding_server do |port|
      sleep(0.1) until nc_port_open?(port.to_i)

      assert_raises(Net::SSH::ConnectionTimeout, 'timeout during server version negotiating') do
        Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd', port: port, timeout: 1) do |ssh|
          ssh.exec! "exit 42"
        end
      end
    end
  end

  def test_error_non_ssh_server
    with_non_responding_server("this is not an SSH server") do |port|
      sleep(0.1) until nc_port_open?(port.to_i)

      assert_raises(Net::SSH::ConnectionTimeout, 'timeout during server version negotiating') do
        Timeout.timeout(2) do
          Net::SSH.start("localhost", "net_ssh_1", password: 'foopwd', port: port, timeout: 1) do |ssh|
            ssh.exec! "exit 42"
          end
        end
      end
    end
  end
end
