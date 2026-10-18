# encoding: ASCII-8BIT

require 'common'
require 'net/ssh/transport/hmac/sha1_etm'

module Transport
  module HMAC
    class TestSHA1_Etm < NetSSHTest
      def test_expected_digest_class
        assert_equal OpenSSL::Digest::SHA1, subject.digest_class
        assert_equal OpenSSL::Digest::SHA1, subject.new.digest_class
      end

      def test_expected_key_length
        assert_equal 20, subject.key_length
        assert_equal 20, subject.new.key_length
      end

      def test_expected_mac_length
        assert_equal 20, subject.mac_length
        assert_equal 20, subject.new.mac_length
      end

      def test_expected_etm
        assert_equal true, subject.etm
        assert_equal true, subject.new.etm
      end

      def test_expected_digest
        hmac = subject.new("1234567890123456")
        assert_equal "\x00\x04W\x82\x84+&\xDD\xC9\xA9P\xB6\xA8\x8C\xBE\x86;\x12U\xF5", hmac.digest("hello world")
      end

      private

      def subject
        Net::SSH::Transport::HMAC::SHA1_Etm
      end
    end
  end
end
