require "common"
require "net/ssh"
require "net/ssh/verifiers/always"
require "net/ssh/verifiers/accept_new_or_local_tunnel"
require "net/ssh/authentication/certificate"
require "tempfile"
require_relative "test_cert_authority_checks"

# Regression tests for GHSA-hjwv-j52r-xcg7: a @revoked known_hosts line was
# loaded as a trusted key, so the key it revoked authenticated the host.
class TestRevokedHostKeys < NetSSHTest
  HOST = "victim.test"
  Session = Struct.new(:host_keys, :port, :peer)
  VERIFIERS = [
    Net::SSH::Verifiers::Always,
    Net::SSH::Verifiers::AcceptNew,
    Net::SSH::Verifiers::AcceptNewOrLocalTunnel
  ]

  def test_revoked_key_is_refused_by_every_verifier
    VERIFIERS.each do |verifier|
      with_known_hosts("@revoked #{HOST} #{line(revoked_key)}") do |path|
        assert_raises(Net::SSH::HostKeyRevoked) { verify(verifier, path, revoked_key) }
      end
    end
  end

  def test_revoked_wildcard_is_refused
    with_known_hosts("@revoked * #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::Always, path, revoked_key) }
    end
  end

  def test_revocation_beats_a_pin_of_the_same_key
    with_known_hosts("#{HOST} #{line(revoked_key)}", "@revoked #{HOST} #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::Always, path, revoked_key) }
    end
  end

  def test_indented_revoked_line_is_honoured
    with_known_hosts("  @revoked #{HOST} #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::Always, path, revoked_key) }
    end
  end

  def test_hashed_revoked_line_is_honoured
    salt = "0123456789abcdefghij"
    hash = OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha1"), salt, HOST)
    hashed = "|1|#{[salt].pack('m0')}|#{[hash].pack('m0')}"
    with_known_hosts("@revoked #{hashed} #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::Always, path, revoked_key) }
    end
  end

  def test_revoked_line_for_the_ip_is_honoured
    with_known_hosts("@revoked 192.0.2.1 #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) do
        verify(Net::SSH::Verifiers::Always, path, revoked_key, host: "#{HOST},192.0.2.1")
      end
    end
  end

  def test_check_host_ip_does_not_narrow_a_revocation
    with_known_hosts("@revoked #{HOST},other.test #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) do
        verify(Net::SSH::Verifiers::Always, path, revoked_key, host: "#{HOST},192.0.2.1", check_host_ip: true)
      end
    end
  end

  def test_accept_new_does_not_remember_a_revoked_key
    with_known_hosts("@revoked #{HOST} #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::AcceptNew, path, revoked_key) }
      assert_equal 1, File.readlines(path).count
    end
  end

  def test_revoked_key_is_refused_on_a_local_tunnel
    with_known_hosts("@revoked #{HOST} #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) do
        verify(Net::SSH::Verifiers::AcceptNewOrLocalTunnel, path, revoked_key, port: 2222)
      end
    end
  end

  def test_local_tunnel_still_accepts_other_keys
    with_known_hosts("@revoked #{HOST} #{line(revoked_key)}") do |path|
      assert verify(Net::SSH::Verifiers::AcceptNewOrLocalTunnel, path, other_key, port: 2222)
    end
  end

  def test_remember_host_can_not_override_a_revocation
    with_known_hosts("@revoked #{HOST} #{line(revoked_key)}") do |path|
      error = assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::Always, path, revoked_key) }
      assert_raises(Net::SSH::HostKeyRevoked) { error.remember_host! }
      assert_equal 1, File.readlines(path).count
    end
  end

  def test_other_key_is_checked_against_the_remaining_pins
    with_known_hosts("@revoked #{HOST} #{line(revoked_key)}", "#{HOST} #{line(other_key)}") do |path|
      assert verify(Net::SSH::Verifiers::Always, path, other_key)
      assert_raises(Net::SSH::HostKeyMismatch) { verify(Net::SSH::Verifiers::Always, path, third_key) }
    end
  end

  def test_host_with_only_a_revoked_line_is_unknown_for_other_keys
    with_known_hosts("@revoked #{HOST} #{line(revoked_key)}") do |path|
      assert_raises(Net::SSH::HostKeyUnknown) { verify(Net::SSH::Verifiers::Always, path, other_key) }
    end
  end

  def test_revoked_line_for_another_host_does_not_apply
    with_known_hosts("@revoked other.test #{line(revoked_key)}", "#{HOST} #{line(revoked_key)}") do |path|
      assert verify(Net::SSH::Verifiers::Always, path, revoked_key)
    end
  end

  def test_certificate_of_a_revoked_key_is_refused
    with_known_hosts("@cert-authority #{HOST} #{line(cert.signature_key)}", "@revoked #{HOST} #{line(cert.key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::Always, path, cert) }
    end
  end

  def test_certificate_signed_by_a_revoked_ca_is_refused
    with_known_hosts("@cert-authority #{HOST} #{line(cert.signature_key)}", "@revoked #{HOST} #{line(cert.signature_key)}") do |path|
      assert_raises(Net::SSH::HostKeyRevoked) { verify(Net::SSH::Verifiers::Always, path, cert) }
    end
  end

  def test_revoked_lines_are_not_returned_as_keys
    with_known_hosts("@revoked #{HOST} #{line(revoked_key)}") do |path|
      assert_empty Net::SSH::KnownHosts.new(path).keys_for(HOST)
      assert_empty Net::SSH::KnownHosts.search_for(HOST, known_hosts_options(path)).to_a
    end
  end

  private

  def revoked_key
    @revoked_key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def other_key
    @other_key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def third_key
    @third_key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def cert
    @cert ||= Net::SSH::Buffer.new(CertAuthorityCheckFixtures::SIGNED_CERT).read_key
  end

  def line(key)
    "#{key.ssh_type} #{[key.to_blob].pack('m0')}"
  end

  def known_hosts_options(path, **options)
    { user_known_hosts_file: path, global_known_hosts_file: [] }.merge(options)
  end

  def with_known_hosts(*lines)
    Tempfile.create("known_hosts") do |file|
      file.puts(lines)
      file.close
      yield file.path
    end
  end

  def verify(verifier, path, key, port: 22, **options)
    host = options.delete(:host) || HOST
    host_keys = Net::SSH::KnownHosts.search_for(host, known_hosts_options(path, **options))
    session = Session.new(host_keys, port, { ip: "127.0.0.1" })
    verifier.new.verify(session: session, key: key, fingerprint: "fp")
  end
end
