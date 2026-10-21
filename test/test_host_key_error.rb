# frozen_string_literal: true

require_relative 'common'

class TestHostKeyError < NetSSHTest
  FakeSession = Struct.new(:host, :port, :socket)
  FakeSocket = Struct.new(:peer_ip)

  def test_host_port_and_ip_on_default_port
    error = mismatch(host: "example.com", port: 22, peer_ip: "10.0.0.5")
    assert_equal "example.com", error.host
    assert_equal 22, error.port
    assert_equal "10.0.0.5", error.ip
  end

  def test_host_port_and_ip_on_non_default_port
    error = mismatch(host: "example.com", port: 2222, peer_ip: "10.0.0.5")
    assert_equal "example.com", error.host
    assert_equal 2222, error.port
    assert_equal "10.0.0.5", error.ip
  end

  def test_ip_is_nil_through_proxy_command
    error = mismatch(host: "example.com", port: 22, peer_ip: Net::SSH::Transport::PacketStream::PROXY_COMMAND_HOST_IP)
    assert_equal "example.com", error.host
    assert_nil error.ip
  end

  def test_accessors_are_nil_without_session
    error = Net::SSH::HostKeyMismatch.new("mismatch")
    error.data = { fingerprint: "SHA256:x" }
    assert_nil error.host
    assert_nil error.port
    assert_nil error.ip
  end

  private

  def mismatch(host:, port:, peer_ip:)
    session = FakeSession.new(host, port, FakeSocket.new(peer_ip))
    error = Net::SSH::HostKeyMismatch.new("mismatch")
    error.data = { fingerprint: "SHA256:x", session: session }
    error
  end
end
