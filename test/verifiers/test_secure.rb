require 'common'
require 'net/ssh/verifiers/secure'
require 'ostruct'

class TestSecure < Test::Unit::TestCase
  def test_raises_unknown_key_error_if_empty
    secure_verifier = Net::SSH::Verifiers::Secure.new
    host_keys = []
    def host_keys.host
      'foo'
    end
    assert_raises(Net::SSH::HostKeyUnknown) {
      secure_verifier.verify(session:OpenStruct.new(host_keys:host_keys))
    }
  end

  def test_passess_if_sam
    secure_verifier = Net::SSH::Verifiers::Secure.new
    key = OpenStruct.new(ssh_type:'key_type',to_blob:'keyblob')
    host_keys = [key]
    def host_keys.host
      'foo'
    end
    secure_verifier.verify(session:OpenStruct.new(host_keys:host_keys), key:key)
  end

  def test_raises_mismatch_error_if_not_the_same
    secure_verifier = Net::SSH::Verifiers::Secure.new
    key_in_known_hosts = OpenStruct.new(ssh_type:'key_type',to_blob:'keyblob')
    key_actual = OpenStruct.new(ssh_type:'key_type',to_blob:'not keyblob')

    host_keys = [key_in_known_hosts]
    def host_keys.host
      'foo'
    end
    assert_raises(Net::SSH::HostKeyMismatch) {
      secure_verifier.verify(session:OpenStruct.new(host_keys:host_keys), key:key_actual)
    }
  end
end