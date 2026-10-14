require_relative '../common'
require 'net/ssh'

module NetSSH
  class TestStartOptions < NetSSHTest
    def setup
      authentication_session = mock('authentication_session')
      authentication_session.stubs(:authenticate).returns(true)
      Net::SSH::Authentication::Session.stubs(:new).returns(authentication_session)
      Net::SSH::Transport::Session.stubs(:new).returns(mock('transport_session'))
      Net::SSH::Connection::Session.stubs(:new).returns(mock('connection_session'))
    end

    def test_start_should_accept_keepalive_option
      assert_nothing_raised do
        options = { keepalive: true }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_keepalive_interval_option
      assert_nothing_raised do
        options = { keepalive_interval: 10 }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_no_delay_option
      assert_nothing_raised do
        options = { no_delay: false }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_send_env_option
      assert_nothing_raised do
        options = { send_env: [/^LC_.*$/, "LANG"] }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_set_env_option
      assert_nothing_raised do
        options = { set_env: { foo: 'bar', baz: 'whale will' } }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_number_of_password_prompts_option
      assert_nothing_raised do
        options = { number_of_password_prompts: 2 }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_append_all_supported_algorithms_option
      assert_nothing_raised do
        options = { append_all_supported_algorithms: true }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_non_interactive_option
      assert_nothing_raised do
        options = { non_interactive: true }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_pubkey_algorithms_option
      assert_nothing_raised do
        options = { pubkey_algorithms: %w[ssh-rsa] }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_start_should_accept_remote_user_option
      assert_nothing_raised do
        options = { remote_user: 'foo' }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_constructor_should_reject_options_set_to_nil
      Kernel.expects(:warn).with { |message| message =~ /remote_user/ }.once

      options = { remote_user: nil }
      Net::SSH.start('localhost', 'testuser', options)
    end

    def test_constructor_should_reject_options_set_to_array_of_nil
      Kernel.expects(:warn).with { |message| message =~ /keys/ }.once

      ENV.delete('no-such-env-variable')
      Net::SSH.start('localhost', 'testuser', keys: [ENV['no-such-env-variable']])
    end

    def test_constructor_should_not_reject_nil_password_options_for_cap_v2_compatibility
      assert_nothing_raised do
        options = { password: nil }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_constructor_should_not_reject_nil_passpharse
      assert_nothing_raised do
        options = { passphrase: nil }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_constructor_should_reject_invalid_options
      assert_raises(ArgumentError) do
        options = { some_invalid_option: "some setting" }
        Net::SSH.start('localhost', 'testuser', options)
      end
    end

    def test_constructor_should_set_default_options
      options = { logger: nil, password_prompt: nil }
      effective_options = start_and_capture_transport_options(options)
      assert !effective_options[:logger].nil?
      assert !effective_options[:password_prompt].nil?
      assert_equal({ logger: nil, password_prompt: nil }, options)
    end

    def test_start_should_accept_frozen_options
      options = { port: 2222, password: nil, paranoid: false }.freeze
      effective_options = start_and_capture_transport_options(options)
      assert_equal 2222, effective_options[:port]
      assert_equal false, effective_options[:verify_host_key]
      assert_equal({ port: 2222, password: nil, paranoid: false }, options)
    end

    def test_start_should_leave_reused_options_unchanged
      options = { port: 2222, password: nil, paranoid: false, non_interactive: true }
      original = options.dup
      Net::SSH.start('localhost', 'testuser', options)
      assert_equal original, options
      Net::SSH.start('localhost', 'otheruser', options)
      assert_equal original, options
    end

    private

    def start_and_capture_transport_options(options)
      effective_options = nil
      Net::SSH::Transport::Session.expects(:new).with { |_host, opts| effective_options = opts }.returns(mock('transport_session'))
      Net::SSH.start('localhost', 'testuser', options)
      effective_options
    end
  end
end
