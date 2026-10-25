require_relative '../common'
require 'net/ssh'
require 'tempfile'

module NetSSH
  class TestStartOptions < NetSSHTest
    def setup
      authentication_session = mock('authentication_session')
      authentication_session.stubs(:authenticate).returns(true)
      Net::SSH::Authentication::Session.stubs(:new).returns(authentication_session)
      Net::SSH::Transport::Session.stubs(:new).returns(mock('transport_session'))
      Net::SSH::Connection::Session.stubs(:new).returns(mock('connection_session'))
    end

    def with_ssh_config(content)
      Tempfile.create('ssh_config') do |file|
        file.write(content)
        file.close
        yield file.path
      end
    end

    def start_and_capture_transport_options(options)
      effective_options = nil
      Net::SSH::Transport::Session.expects(:new).with { |_host, opts| effective_options = opts }.returns(mock('transport_session'))
      Net::SSH.start('localhost', 'testuser', options)
      effective_options
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

    def test_start_with_paranoid_raises_naming_verify_host_key
      error = assert_raises(ArgumentError) do
        Net::SSH.start('localhost', 'testuser', paranoid: :always)
      end
      assert_equal ":paranoid has been removed, use :verify_host_key (same values)", error.message
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

    def test_start_should_raise_for_nil_options
      %i[proxy port config remote_user].each do |key|
        Net::SSH::Transport::Session.expects(:new).never
        error = assert_raises(ArgumentError) { Net::SSH.start('localhost', 'testuser', key => nil) }
        assert_match(/\Anil is not allowed for #{key.inspect}; omit it to use the default or ssh_config value/, error.message)
      end
    end

    def test_start_should_raise_for_arrays_containing_nil
      ENV.delete('no-such-env-variable')
      [[nil], ['id_rsa', nil], [ENV['no-such-env-variable']]].each do |keys|
        error = assert_raises(ArgumentError) { Net::SSH.start('localhost', 'testuser', keys: keys) }
        assert_match(/\Anil is not allowed for :keys;/, error.message)
      end
    end

    def test_nil_option_error_message_includes_hint
      error = assert_raises(ArgumentError) { Net::SSH.start('localhost', 'testuser', proxy: nil) }
      assert_equal "nil is not allowed for :proxy; omit it to use the default or ssh_config value, " \
                   "or pass proxy: false to connect without a proxy", error.message
    end

    def test_nil_option_error_message_lists_all_keys_and_their_hints
      error = assert_raises(ArgumentError) { Net::SSH.start('localhost', 'testuser', port: nil, keys: [nil], config: nil) }
      assert_equal "nil is not allowed for :port, :keys, :config; omit them to use the default or ssh_config value, " \
                   "or pass keys: [] to use no key files, or config: false to skip ssh_config files", error.message
    end

    def test_nil_options_should_not_warn
      Kernel.expects(:warn).never
      assert_raises(ArgumentError) { Net::SSH.start('localhost', 'testuser', port: nil) }
      Net::SSH.start('localhost', 'testuser', password: nil, passphrase: nil, logger: nil, password_prompt: nil)
    end

    def test_nil_options_should_not_modify_callers_hash
      options = { port: nil }
      assert_raises(ArgumentError) { Net::SSH.start('localhost', 'testuser', options) }
      assert_equal({ port: nil }, options)
    end

    def test_match_user_should_use_the_start_user
      with_ssh_config("Match User alice Host localhost\n  Port 2200\n") do |path|
        assert_equal 2200, start_and_capture_transport_options_as('alice', config: path)[:port]
        assert_nil start_and_capture_transport_options_as('bob', config: path)[:port]
        assert_equal 2200, start_and_capture_transport_options_as(nil, config: path, user: 'alice')[:port]
      end
    end

    def test_match_user_should_use_user_from_ssh_config_when_user_is_nil
      with_ssh_config("Host localhost\n  User alice\nMatch User alice\n  Port 2200\n") do |path|
        assert_equal 2200, start_and_capture_transport_options_as(nil, config: path)[:port]
        assert_nil start_and_capture_transport_options_as('bob', config: path)[:port]
      end
    end

    def start_and_capture_transport_options_as(user, options)
      effective_options = nil
      Net::SSH::Transport::Session.expects(:new).with { |_host, opts| effective_options = opts }.returns(mock('transport_session'))
      Net::SSH.start('localhost', user, options)
      effective_options
    end

    def test_config_false_should_skip_ssh_config
      Net::SSH::Config.expects(:for).never
      Net::SSH.start('localhost', 'testuser', config: false)
    end

    def test_hinted_values_should_override_ssh_config
      overrides = {
        "ProxyCommand nc %h %p" => { proxy: false },
        "IdentityFile ~/.ssh/from_config" => { keys: [] },
        "ForwardAgent yes" => { forward_agent: false },
        "ServerAliveInterval 10" => { keepalive: false },
        "Compression yes" => { compression: false },
        "SendEnv LANG" => { send_env: [] },
        "SetEnv FOO=bar" => { set_env: {} }
      }
      overrides.each do |config_line, override|
        key, value = override.first
        with_ssh_config("Host *\n  #{config_line}\n") do |config|
          refute_includes [nil, false, [], {}], start_and_capture_transport_options(config: config)[key], config_line
          assert_equal value, start_and_capture_transport_options(config: config, **override)[key]
        end
      end
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
      options = { port: 2222, password: nil, verify_host_key: :never }.freeze
      effective_options = start_and_capture_transport_options(options)
      assert_equal 2222, effective_options[:port]
      assert_equal :never, effective_options[:verify_host_key]
      assert_equal({ port: 2222, password: nil, verify_host_key: :never }, options)
    end

    def test_start_should_leave_reused_options_unchanged
      options = { port: 2222, password: nil, verify_host_key: :never, non_interactive: true }
      original = options.dup
      Net::SSH.start('localhost', 'testuser', options)
      assert_equal original, options
      Net::SSH.start('localhost', 'otheruser', options)
      assert_equal original, options
    end
  end
end
