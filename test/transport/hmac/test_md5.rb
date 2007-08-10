$LOAD_PATH.unshift("#{File.dirname(__FILE__)}/../..").uniq!
require 'common'
require 'net/ssh/transport/hmac/md5'

module Transport; module HMAC

  class TestMD5 < Test::Unit::TestCase
    def test_expected_digest_class
      assert_equal OpenSSL::Digest::MD5, subject.digest_class
      assert_equal OpenSSL::Digest::MD5, subject.new.digest_class
    end

    def test_expected_key_length
      assert_equal 16, subject.key_length
      assert_equal 16, subject.new.key_length
    end

    def test_expected_mac_length
      assert_equal 16, subject.mac_length
      assert_equal 16, subject.new.mac_length
    end

    def test_expected_digest
      hmac = subject.new("1234567890123456")
      assert_equal "\275\345\006\307y~Oi\035<.\341\031\250<\257", hmac.digest("hello world")
    end

    private

      def subject
        Net::SSH::Transport::HMAC::MD5
      end
  end

end; end