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
      @previous_default_configuration = Net::SSH.default_configuration
    end

    def teardown
      Net::SSH.default_configuration = @previous_default_configuration
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
      Net::SSH.start('localhost', 'testuser', options)
      assert !options[:logger].nil?
      assert !options[:password_prompt].nil?
    end

    def test_default_configuration_and_precedence
      Net::SSH::Config.stubs(:for).with('localhost', Net::SSH::Config.expandable_default_files)
                      .returns({ timeout: 5, password: 'from_file' })

      Net::SSH.default_configuration = lambda do |_host, ssh_config|
        { timeout: 10, keepalive: true, password: ssh_config.fetch(:password, 'from_default_configuration') }
      end

      Net::SSH::Connection::Session
        .expects(:new)
        .with(anything, has_entries(timeout: 10, keepalive: false, password: 'from_file'))
        .returns(mock('connection_session'))

      options = { keepalive: false }
      Net::SSH.start('localhost', 'testuser', options)

      # Test that original options are not modified.
      assert_nil options[:timeout]
      assert_nil options[:password]
    end

    def test_default_configuration_and_config_false
      Net::SSH.default_configuration = lambda do |*|
        { keepalive: true }
      end

      Net::SSH::Connection::Session
        .expects(:new)
        .with(anything, has_entries(keepalive: true))
        .returns(mock('connection_session'))

      options = { config: false }
      Net::SSH.start('localhost', 'testuser')

      # Test that original options are not modified.
      assert_nil options[:keepalive]
    end
  end
end
