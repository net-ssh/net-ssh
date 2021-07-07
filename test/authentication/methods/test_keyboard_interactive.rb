require_relative '../../common'
require 'net/ssh/authentication/methods/keyboard_interactive'
require_relative 'common'

module Authentication
  module Methods
    class TestKeyboardInteractive < NetSSHTest
      include Common

      USERAUTH_INFO_REQUEST  = 60
      USERAUTH_INFO_RESPONSE = 61

      def setup
        reset_subject({}) if defined? @subject && !@subject.options.empty?
      end

      def test_authenticate_should_raise_if_keyboard_interactive_disallowed
        transport.expect do |t,packet|
          assert_equal USERAUTH_REQUEST, packet.type
          assert_equal "jamis", packet.read_string
          assert_equal "ssh-connection", packet.read_string
          assert_equal "keyboard-interactive", packet.read_string
          assert_equal "", packet.read_string # language tags
          assert_equal "", packet.read_string # submethods

          t.return(USERAUTH_FAILURE, :string, "password")
        end

        assert_raises Net::SSH::Authentication::DisallowedMethod do
          subject.authenticate("ssh-connection", "jamis")
        end
      end

      def test_authenticate_should_be_false_if_given_password_is_not_accepted
        reset_subject(non_interactive: true)

        transport.expect do |t,packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2,packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 1, packet2.read_long
            assert_equal "the-password", packet2.read_string
            t2.return(USERAUTH_FAILURE, :string, "keyboard-interactive")
          end
        end

        assert_equal false, subject.authenticate("ssh-connection", "jamis", "the-password")
      end

      def test_authenticate_should_be_true_if_given_password_is_accepted
        transport.expect do |t,packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 1, :string, "Password:", :bool, false)
          t.expect do |t2,packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", "the-password")
      end

      def test_authenticate_should_duplicate_password_as_needed_to_fill_request
        transport.expect do |t,packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 2, :string, "Password:", :bool, false, :string, "Again:", :bool, false)
          t.expect do |t2,packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "the-password", packet2.read_string
            assert_equal "the-password", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", "the-password")
      end

      def test_authenticate_should_not_prompt_for_input_when_in_non_interactive_mode
        reset_subject(non_interactive: true)
        transport.expect do |t,packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 2, :string, "Name:", :bool, true, :string, "Password:", :bool, false)
          t.expect do |t2,packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "", packet2.read_string
            assert_equal "", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
      end

      def test_authenticate_should_prompt_for_input_when_password_is_not_given
        prompt = MockPrompt.new
        prompt.expects(:_ask).with("Name:", anything, true).returns("name")
        prompt.expects(:_ask).with("Password:", anything, false).returns("password")
        reset_subject(password_prompt: prompt)

        transport.expect do |t,packet|
          assert_equal USERAUTH_REQUEST, packet.type
          t.return(USERAUTH_INFO_REQUEST, :string, "", :string, "", :string, "", :long, 2, :string, "Name:", :bool, true, :string, "Password:", :bool, false)
          t.expect do |t2,packet2|
            assert_equal USERAUTH_INFO_RESPONSE, packet2.type
            assert_equal 2, packet2.read_long
            assert_equal "name", packet2.read_string
            assert_equal "password", packet2.read_string
            t2.return(USERAUTH_SUCCESS)
          end
        end

        assert subject.authenticate("ssh-connection", "jamis", nil)
      end

      private

      def subject(options={})
        @subject ||= Net::SSH::Authentication::Methods::KeyboardInteractive.new(session(options), options)
      end

      def reset_subject(options)
        @subject = nil
        reset_session(options)
        subject(options)
      end
    end
  end
end
