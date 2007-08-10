$LOAD_PATH.unshift("#{File.dirname(__FILE__)}/..").uniq!
require 'common'
require 'net/ssh/transport/hmac'

module Transport

  class TestHMAC < Test::Unit::TestCase
    MAP = {
      'hmac-md5'     => Net::SSH::Transport::HMAC::MD5,
      'hmac-md5-96'  => Net::SSH::Transport::HMAC::MD5_96,
      'hmac-sha1'    => Net::SSH::Transport::HMAC::SHA1,
      'hmac-sha1-96' => Net::SSH::Transport::HMAC::SHA1_96,
      'none'         => Net::SSH::Transport::HMAC::None
    }

    MAP.each do |name, value|
      method = name.tr("-", "_")
      define_method("test_find_with_#{method}_returns_correct_hmac_class") do
        assert_equal value, Net::SSH::Transport::HMAC.find(name)
      end

      define_method("test_get_with_#{method}_returns_new_hmac_instance") do
        key = "abcdefghijklmnopqrstuvwxyz"[0..MAP[name].key_length]
        hmac = Net::SSH::Transport::HMAC.get(name, key)
        assert_instance_of MAP[name], hmac
        assert_equal key, hmac.key
      end

      define_method("test_key_length_with_#{method}_returns_correct_key_length") do
        assert_equal MAP[name].key_length, Net::SSH::Transport::HMAC.key_length(name)
      end
    end

    def test_find_with_unrecognized_hmac_returns_nil
      assert_nil Net::SSH::Transport::HMAC.find("bogus")
    end

    def test_get_with_unrecognized_hmac_raises_argument_error
      assert_raises(ArgumentError) do
        Net::SSH::Transport::HMAC.get("bogus")
      end
    end

    def test_key_length_with_unrecognized_hmac_raises_argument_error
      assert_raises(ArgumentError) do
        Net::SSH::Transport::HMAC.get("bogus")
      end
    end
  end

end