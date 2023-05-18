require_relative '../common'
require 'logger'
require 'net/ssh/transport/aead_aes_gcm'

module Transport
  class TestAEADAESGCM < NetSSHTest
    def gcm_cipher
      iv = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
      Net::SSH::Transport::CipherFactory.get('aes256-gcm@openssh.com',
                                             iv: iv,
                                             key: '1' * 32,
                                             shared: 'toto',
                                             hash: 'XYZZYXXYZZYX',
                                             digester: 'none')
    end

    def test_iv_increment_when_64_bit_long
      cipher = gcm_cipher
      cipher.incr_iv
      assert_equal cipher.instance_variable_get(:@iv), { fixed: "\xFF\xFF\xFF\xFF", invocation_counter: "\x00\x00\x00\x00\x00\x00\x00\x00" }
    end

    def test_block_size
      assert_equal gcm_cipher.block_size, 16
    end
  end
end
