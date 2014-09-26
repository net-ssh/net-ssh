require 'common'
require 'net/ssh/authentication/methods/password'
require 'net/ssh/authentication/session'
require 'authentication/methods/common'


module Authentication; module Methods

  class TestPassword < Test::Unit::TestCase
    include Common

    def test_authenticate_should_raise_if_password_disallowed
      transport.expect do |t,packet|
        assert_equal USERAUTH_REQUEST, packet.type
        assert_equal "jamis", packet.read_string
        assert_equal "ssh-connection", packet.read_string
        assert_equal "password", packet.read_string
        assert_equal false, packet.read_bool
        assert_equal "the-password", packet.read_string

        t.return(USERAUTH_FAILURE, :string, "publickey")
      end

      assert_raises Net::SSH::Authentication::DisallowedMethod do
        subject.authenticate("ssh-connection", "jamis", "the-password")
      end
    end

    def test_authenticate_ask_for_password_for_second_time_when_password_is_incorrect
      transport.expect do |t,packet|
        assert_equal USERAUTH_REQUEST, packet.type
        assert_equal "jamis", packet.read_string
        assert_equal "ssh-connection", packet.read_string
        assert_equal "password", packet.read_string
        assert_equal false, packet.read_bool
        assert_equal "the-password", packet.read_string
        t.return(USERAUTH_FAILURE, :string, "publickey,password")

        t.expect do |t2, packet2|
          assert_equal USERAUTH_REQUEST, packet2.type
          assert_equal "jamis", packet2.read_string
          assert_equal "ssh-connection", packet2.read_string
          assert_equal "password", packet2.read_string
          assert_equal false, packet2.read_bool
          assert_equal "the-password-2", packet2.read_string
          t.return(USERAUTH_SUCCESS)
        end
      end

      subject.expects(:prompt).with("jamis@'s password:", false).returns("the-password-2")
      subject.authenticate("ssh-connection", "jamis", "the-password")
    end

    def test_authenticate_ask_for_password_if_not_given
      transport.expect do |t,packet|
        assert_equal USERAUTH_REQUEST, packet.type
        assert_equal "bill", packet.read_string
        assert_equal "ssh-connection", packet.read_string
        assert_equal "password", packet.read_string
        assert_equal false, packet.read_bool
        assert_equal "good-password", packet.read_string
        t.return(USERAUTH_SUCCESS)
      end

      transport.instance_eval { @host='testhost' }
      subject.expects(:prompt).with("bill@testhost's password:", false).returns("good-password")
      subject.authenticate("ssh-connection", "bill", nil)
    end

    def test_authenticate_when_password_is_acceptible_should_return_true
      transport.expect do |t,packet|
        assert_equal USERAUTH_REQUEST, packet.type
        t.return(USERAUTH_SUCCESS)
      end

      assert subject.authenticate("ssh-connection", "jamis", "the-password")
    end

    def test_authenticate_should_return_false_if_password_change_request_is_received
      transport.expect do |t,packet|
        assert_equal USERAUTH_REQUEST, packet.type
        t.return(USERAUTH_PASSWD_CHANGEREQ, :string, "Change your password:", :string, "")
      end

      assert !subject.authenticate("ssh-connection", "jamis", "the-password")
    end

    private

      def subject(options={})
        @subject ||= Net::SSH::Authentication::Methods::Password.new(session(options), options)
      end
  end

end; end
