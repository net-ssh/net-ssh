# encoding: ASCII-8BIT
# frozen_string_literal: false

require_relative '../common'
require 'net/ssh/buffer'
require 'net/ssh/authentication/security_key'

module Authentication
  class TestSecurityKey < NetSSHTest
    SK_ECDSA = Net::SSH::Authentication::SecurityKey::SK_ECDSA_SHA2_NISTP256
    SK_ED25519 = Net::SSH::Authentication::SecurityKey::SK_SSH_ED25519

    # 65-byte uncompressed NIST P-256 point (0x04 || X || Y).
    ECDSA_POINT = "\x04#{"\x11" * 64}".b
    ED25519_POINT = ("\x22" * 32).b

    def sk_ecdsa_blob(application = "ssh:")
      Net::SSH::Buffer.from(:string, SK_ECDSA, :string, "nistp256",
                            :string, ECDSA_POINT, :string, application).to_s
    end

    def sk_ed25519_blob(application = "ssh:")
      Net::SSH::Buffer.from(:string, SK_ED25519, :string, ED25519_POINT,
                            :string, application).to_s
    end

    def test_buffer_read_key_returns_security_key_pubkey_for_sk_ecdsa
      key = Net::SSH::Buffer.new(sk_ecdsa_blob).read_key
      assert_instance_of Net::SSH::Authentication::SecurityKey::PubKey, key
      assert_equal SK_ECDSA, key.ssh_type
      assert_equal "nistp256", key.curve
      assert_equal ECDSA_POINT, key.public_key_data
      assert_equal "ssh:", key.application
    end

    def test_buffer_read_key_returns_security_key_pubkey_for_sk_ed25519
      key = Net::SSH::Buffer.new(sk_ed25519_blob).read_key
      assert_instance_of Net::SSH::Authentication::SecurityKey::PubKey, key
      assert_equal SK_ED25519, key.ssh_type
      assert_nil key.curve
      assert_equal ED25519_POINT, key.public_key_data
      assert_equal "ssh:", key.application
    end

    def test_to_blob_round_trips_sk_ecdsa
      blob = sk_ecdsa_blob
      assert_equal blob, Net::SSH::Buffer.new(blob).read_key.to_blob
    end

    def test_to_blob_round_trips_sk_ed25519
      blob = sk_ed25519_blob
      assert_equal blob, Net::SSH::Buffer.new(blob).read_key.to_blob
    end

    def test_fingerprint_uses_openssh_sha256_format
      blob = sk_ecdsa_blob
      key = Net::SSH::Buffer.new(blob).read_key
      expected = "SHA256:#{[OpenSSL::Digest.digest('SHA256', blob)].pack('m').chomp.delete('=')}"
      assert_equal expected, key.fingerprint('SHA256')
    end

    def test_ssh_signature_type_is_key_type
      key = Net::SSH::Buffer.new(sk_ed25519_blob).read_key
      assert_equal SK_ED25519, key.ssh_signature_type
    end

    def test_understands_only_known_sk_types
      assert Net::SSH::Authentication::SecurityKey.understands?(SK_ECDSA)
      assert Net::SSH::Authentication::SecurityKey.understands?(SK_ED25519)
      refute Net::SSH::Authentication::SecurityKey.understands?("ssh-ed25519")
      refute Net::SSH::Authentication::SecurityKey.understands?("ecdsa-sha2-nistp256")
    end

    def test_unknown_type_still_raises
      blob = Net::SSH::Buffer.from(:string, "totally-unknown", :string, "x").to_s
      assert_raises(NotImplementedError) { Net::SSH::Buffer.new(blob).read_key }
    end
  end
end
