require 'common'
require 'net/ssh/verifiers/always'
require 'ostruct'

class TestAlways < NetSSHTest
  def test_raises_unknown_key_error_if_empty
    secure_verifier = Net::SSH::Verifiers::Always.new
    host_keys = []
    def host_keys.host
      'foo'
    end
    assert_raises(Net::SSH::HostKeyUnknown) {
      secure_verifier.verify(session: OpenStruct.new(host_keys: host_keys))
    }
  end

  def test_passess_if_sam
    secure_verifier = Net::SSH::Verifiers::Always.new
    key = OpenStruct.new(ssh_type: 'key_type', to_blob: 'keyblob')
    host_keys = [key]
    def host_keys.host
      'foo'
    end
    secure_verifier.verify(session: OpenStruct.new(host_keys: host_keys), key: key)
  end

  def test_raises_mismatch_error_if_not_the_same
    secure_verifier = Net::SSH::Verifiers::Always.new
    key_in_known_hosts = OpenStruct.new(ssh_type: 'key_type', to_blob: 'keyblob')
    key_actual = OpenStruct.new(ssh_type: 'key_type', to_blob: 'not keyblob')

    host_keys = [key_in_known_hosts]
    def host_keys.host
      'foo'
    end
    assert_raises(Net::SSH::HostKeyMismatch) {
      secure_verifier.verify(session: OpenStruct.new(host_keys: host_keys), key: key_actual)
    }
  end

  def test_verify_signature
    secure_verifier = Net::SSH::Verifiers::Always.new

    assert(true, secure_verifier.verify_signature { true })
  end
end

class TestAlwaysCertAuthority < NetSSHTest
  # A host_keys collection with a @cert-authority-style entry.
  # `ca_opts` are forwarded to MockCertAuthorityEntry.
  def make_session(hostname: "server.example.com", **ca_opts)
    ca_entry = MockCertAuthorityEntry.new(**ca_opts)
    host_keys = [ca_entry]
    host_keys.define_singleton_method(:host) { "server.example.com" }
    host_keys.define_singleton_method(:hostname) { hostname }
    OpenStruct.new(host_keys: host_keys)
  end

  def cert(valid_principals: ["server.example.com"], valid_before: nil, valid_after: nil)
    OpenStruct.new(
      valid_principals: valid_principals,
      valid_before: valid_before,
      valid_after: valid_after
    )
  end

  def test_passes_when_cert_is_valid_and_principal_matches
    verifier = Net::SSH::Verifiers::Always.new
    verifier.verify(session: make_session, key: cert)
  end

  def test_raises_host_key_unknown_when_principal_does_not_match
    verifier = Net::SSH::Verifiers::Always.new
    assert_raises(Net::SSH::HostKeyUnknown) do
      verifier.verify(
        session: make_session(matches_principal: false),
        key: cert
      )
    end
  end

  def test_raises_host_key_unknown_when_cert_has_expired
    verifier = Net::SSH::Verifiers::Always.new
    expired_cert = cert(valid_before: Time.now - 3600)
    assert_raises(Net::SSH::HostKeyUnknown) do
      verifier.verify(
        session: make_session(matches_validity: false),
        key: expired_cert
      )
    end
  end

  def test_expired_cert_error_message_says_expired
    verifier = Net::SSH::Verifiers::Always.new
    expired_cert = cert(valid_before: Time.now - 3600)
    error = assert_raises(Net::SSH::HostKeyUnknown) do
      verifier.verify(
        session: make_session(matches_validity: false),
        key: expired_cert
      )
    end
    assert_match(/expired/i, error.message)
  end

  def test_not_yet_valid_cert_error_message_says_not_yet_valid
    verifier = Net::SSH::Verifiers::Always.new
    future_cert = cert(valid_before: Time.now + 7200, valid_after: Time.now + 3600)
    error = assert_raises(Net::SSH::HostKeyUnknown) do
      verifier.verify(
        session: make_session(matches_validity: false),
        key: future_cert
      )
    end
    assert_match(/not yet valid/i, error.message)
  end

  def test_raises_host_key_mismatch_when_ca_does_not_match
    verifier = Net::SSH::Verifiers::Always.new
    assert_raises(Net::SSH::HostKeyMismatch) do
      verifier.verify(
        session: make_session(matches_key: false),
        key: cert
      )
    end
  end

  # A mock @cert-authority-style host key entry that duck-types CertAuthority.
  class MockCertAuthorityEntry
    def initialize(matches_key: true, matches_validity: true, matches_principal: true)
      @matches_key = matches_key
      @matches_validity = matches_validity
      @matches_principal = matches_principal
    end

    def matches_key?(_server_key)
      @matches_key
    end

    def matches_validity?(_server_key)
      @matches_validity
    end

    def matches_principal?(_server_key, _hostname)
      @matches_principal
    end
  end
end
