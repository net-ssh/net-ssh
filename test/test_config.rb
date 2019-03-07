require_relative './common'
require 'net/ssh/config'
require 'net/ssh'
require 'pathname'
require 'tempfile'

class TestConfig < NetSSHTest
  def test_home_should_be_absolute_path
    assert Pathname.new(ENV['HOME']).absolute?
  end

  def test_load_for_non_existant_file_should_return_empty_hash
    bogus_file = File.expand_path("/bogus/file")
    File.expects(:readable?).with(bogus_file).returns(false)
    assert_equal({}, Net::SSH::Config.load(bogus_file, "host.name"))
  end

  def test_load_should_expand_path
    expected = File.expand_path("~/.ssh/config")
    File.expects(:readable?).with(expected).returns(false)
    Net::SSH::Config.load("~/.ssh/config", "host.name")
  end

  def test_load_with_exact_host_match_should_load_that_section
    config = Net::SSH::Config.load(config(:exact_match), "test.host")
    assert config['compression']
    assert config['forwardagent']
    assert_equal 1234, config['port']
  end

  def test_load_with_wild_card_matches_should_load_all_matches_with_first_match_taking_precedence
    config = Net::SSH::Config.load(config(:wild_cards), "test.host")
    assert_equal 1234, config['port']
    assert !config['compression']
    assert config['forwardagent']
    assert_equal %w(~/.ssh/id_dsa), config['identityfile']
    assert !config.key?('rekeylimit')
  end

  def test_load_with_wild_card_and_negative_pattern_does_not_match
    config = Net::SSH::Config.load(config(:negative_match), "test.host")
    assert_equal 9876, config['port']
    assert !config.key?('compression')
  end

  def test_load_with_pattern_does_match
    data = %q{
      Host test.*
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "test.host")
      assert_equal 1234, config['port']
    end
  end

  def test_check_host_ip
    data = %q{
      Host *
        CheckHostIP no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, 'foo')
      assert_equal false, config['checkhostip']

      config = Net::SSH::Config.for("foo", [f])
      assert_equal false, config[:check_host_ip]
    end
  end

  def test_load_with_regex_chars
    data = %q{
      Host |
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "test.host")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "|")
      assert_equal 1234, config['port']
    end
  end

  def test_for_should_load_all_files_and_translate_to_net_ssh_options
    config = Net::SSH::Config.for("test.host", [config(:exact_match), config(:wild_cards)])
    assert_equal 1234, config[:port]
    assert config[:compression]
    assert config[:forward_agent]
    assert_equal %w(~/.ssh/id_dsa), config[:keys]
    assert !config.key?(:rekey_limit)
  end

  def test_load_with_no_host
    config = Net::SSH::Config.load(config(:nohost), "test.host")
    assert_equal %w(~/.ssh/id_dsa ~/.ssh/id_rsa), config['identityfile']
    assert_equal 1985, config['port']
  end

  def test_load_with_multiple_hosts
    config = Net::SSH::Config.load(config(:multihost), "test.host")
    assert config['compression']
    assert_equal '2G', config['rekeylimit']
    assert_equal 1980, config['port']
  end

  def test_load_with_multiple_hosts_and_config_should_match_for_both
    aconfig = Net::SSH::Config.load(config(:multihost), "test.host")
    bconfig = Net::SSH::Config.load(config(:multihost), "other.host")
    assert_equal aconfig['port'], bconfig['port']
    assert_equal aconfig['compression'], bconfig['compression']
    assert_equal aconfig['rekeylimit'], bconfig['rekeylimit']
  end

  def test_load_should_parse_equal_sign_delimiters
    config = Net::SSH::Config.load(config(:eqsign), "test.test")
    assert config['compression']
    assert_equal 1234, config['port']
  end

  def test_translate_should_correctly_translate_from_openssh_to_net_ssh_names
    open_ssh = {
      'bindaddress'             => "127.0.0.1",
      'ciphers'                 => "a,b,c",
      'compression'             => true,
      'compressionlevel'        => 6,
      'connecttimeout'          => 100,
      'forwardagent'            => true,
      'hostbasedauthentication' => true,
      'hostkeyalgorithms'       => "d,e,f",
      'identityfile'            => %w(g h i),
      'macs'                    => "j,k,l",
      'passwordauthentication'  => true,
      'port'                    => 1234,
      'pubkeyauthentication'    => true,
      'rekeylimit'              => 1024,
      'sendenv'                 => "LC_*",
      'numberofpasswordprompts' => '123',
      'serveraliveinterval'     => '2',
      'serveralivecountmax'     => '4',
      'fingerprinthash'         => 'MD5'
    }

    net_ssh = Net::SSH::Config.translate(open_ssh)

    assert_equal %w(a b c), net_ssh[:encryption]
    assert_equal true,      net_ssh[:compression]
    assert_equal 6,         net_ssh[:compression_level]
    assert_equal 100,       net_ssh[:timeout]
    assert_equal true,      net_ssh[:forward_agent]
    assert_equal %w(hostbased keyboard-interactive none password publickey), net_ssh[:auth_methods].sort
    assert_equal %w(d e f), net_ssh[:host_key]
    assert_equal %w(g h i), net_ssh[:keys]
    assert_equal %w(j k l), net_ssh[:hmac]
    assert_equal 1234,      net_ssh[:port]
    assert_equal 1024,      net_ssh[:rekey_limit]
    assert_equal "127.0.0.1", net_ssh[:bind_address]
    assert_equal [/^LC_.*$/], net_ssh[:send_env]
    assert_equal 123,       net_ssh[:number_of_password_prompts]
    assert_equal 4,         net_ssh[:keepalive_maxcount]
    assert_equal 2,         net_ssh[:keepalive_interval]
    assert_equal 'MD5',     net_ssh[:fingerprint_hash]
    assert_equal true, net_ssh[:keepalive]
  end

  def test_translate_should_turn_off_authentication_methods
    open_ssh = {
      'hostbasedauthentication'         => false,
      'passwordauthentication'          => false,
      'pubkeyauthentication'            => false,
      'challengeresponseauthentication' => false,
      'kbdinteractiveauthentication'    => false
    }

    net_ssh = Net::SSH::Config.translate(open_ssh)

    assert_equal %w(none), net_ssh[:auth_methods].sort
  end

  def test_translate_should_turn_on_authentication_methods
    open_ssh = {
      'hostbasedauthentication'         => true,
      'passwordauthentication'          => true,
      'pubkeyauthentication'            => true,
      'challengeresponseauthentication' => true,
      'kbdinteractiveauthentication'    => true
    }

    net_ssh = Net::SSH::Config.translate(open_ssh)

    assert_equal %w(hostbased keyboard-interactive none password publickey), net_ssh[:auth_methods].sort
  end

  def test_translate_should_not_disable_keyboard_interactive_when_challange_or_keyboardinterective_is_on
    open_ssh = {
      'kbdinteractiveauthentication' => false
    }
    net_ssh = Net::SSH::Config.translate(open_ssh)
    assert_equal %w(keyboard-interactive none password publickey), net_ssh[:auth_methods].sort

    open_ssh = {
      'challengeresponseauthentication' => false
    }
    net_ssh = Net::SSH::Config.translate(open_ssh)
    assert_equal %w(keyboard-interactive none password publickey), net_ssh[:auth_methods].sort
  end

  def test_should_ddisable_keyboard_interactive_when_challeng_and_keyboardinteractive_is_off
    open_ssh = {
      'challengeresponseauthentication' => false,
      'kbdinteractiveauthentication' => false
    }

    net_ssh = Net::SSH::Config.translate(open_ssh)
    assert_equal %w(none password publickey), net_ssh[:auth_methods].sort
  end

  def test_for_should_turn_off_authentication_methods
    config = Net::SSH::Config.for("test.host", [config(:empty), config(:auth_off), config(:auth_on)])
    assert_equal %w(none), config[:auth_methods].sort
  end

  def test_for_should_turn_on_authentication_methods
    config = Net::SSH::Config.for("test.host", [config(:empty), config(:auth_on), config(:auth_off)])
    assert_equal %w(hostbased keyboard-interactive none password publickey), config[:auth_methods].sort
  end

  def test_configuration_for_when_HOME_is_null_should_not_raise
    with_home_env(nil) do
      with_restored_default_files do
        Net::SSH.configuration_for("test.host", true)
      end
    end
  end

  def test_config_for_when_HOME_is_null_should_not_raise
    with_home_env(nil) do
      with_restored_default_files do
        Net::SSH::Config.for("test.host")
      end
    end
  end

  def test_load_with_plus_sign_hosts
    config = Net::SSH::Config.load(config(:host_plus), "test.host")
    assert config['compression']
  end

  def test_load_with_numeric_host
    config = Net::SSH::Config.load(config(:numeric_host), "1234")
    assert config['compression']
    assert_equal '2G', config['rekeylimit']
    assert_equal 1980, config['port']
  end

  def test_load_wildcar_with_substitutes
    config = Net::SSH::Config.load(config(:substitutes), "toto")
    net_ssh = Net::SSH::Config.translate(config)
    assert_equal 'toto', net_ssh[:host_name]
  end

  def test_load_sufix_with_substitutes
    config = Net::SSH::Config.load(config(:substitutes), "test")
    net_ssh = Net::SSH::Config.translate(config)
    assert_equal 'test.sufix', net_ssh[:host_name]
  end

  def test_load_prefix_and_sufix_with_substitutes
    config = Net::SSH::Config.load(config(:substitutes), "1234")
    net_ssh = Net::SSH::Config.translate(config)
    assert_equal 'prefix.1234.sufix', net_ssh[:host_name]
  end

  def test_load_with_send_env
    config = Net::SSH::Config.load(config(:send_env), "1234")
    net_ssh = Net::SSH::Config.translate(config)
    assert_equal [/^GIT_.*$/, /^LANG$/, /^LC_.*$/], net_ssh[:send_env]
  end

  def test_load_with_remote_user
    config = Net::SSH::Config.load(config(:proxy_remote_user), "behind-proxy")
    net_ssh = Net::SSH::Config.translate(config)
    assert net_ssh[:proxy]
  end

  def test_load_with_proxy_jump
    config = Net::SSH::Config.load(config(:proxy_jump), "behind-proxy")
    net_ssh = Net::SSH::Config.translate(config)
    assert net_ssh[:proxy]
  end

  def test_load_with_include_keyword
    config = Net::SSH::Config.load(config(:include), "xyz")
    net_ssh = Net::SSH::Config.translate(config)
    assert_equal 'example.com', net_ssh[:host_name]
    assert_equal 'foo', net_ssh[:user]
    assert_equal 2345, net_ssh[:port]
    assert_equal true, net_ssh[:compression]
    assert net_ssh[:keys_only]
    assert_equal %w(~/.ssh/id.pem ~/.ssh/id2.pem ~/.ssh/id3.pem), net_ssh[:keys]
  end

  def test_default_files_not_mutable
    original_default_files = Net::SSH::Config.default_files.clone

    default_files = Net::SSH::Config.default_files
    default_files.push('garbage')

    assert_equal(original_default_files, Net::SSH::Config.default_files)
  end

  def test_default_auth_methods_not_mutable
    original_default_auth_methods = Net::SSH::Config.default_auth_methods.clone

    default_auth_methods = Net::SSH::Config.default_auth_methods
    default_auth_methods.push('garbage')

    assert_equal(original_default_auth_methods, Net::SSH::Config.default_auth_methods)
  end

  def test_load_with_match_block
    config = Net::SSH::Config.load(config(:match), "test.host")
    net_ssh = Net::SSH::Config.translate(config)
    assert_equal true, net_ssh[:forward_agent]
    assert_equal true, net_ssh[:compression]
    assert_equal 22, net_ssh[:port]
  end

  def test_load_with_match_block_with_host
    data = %q{
      Match Host foo
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_hosts
    data = %q{
      Match Host foo,bar
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar")
      assert_equal 1234, config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_hosts_wildcard
    data = %q{
      Match Host foo,*.baz.com
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_equal 1234, config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_multi_space_separated_hosts_condition
    # Extra tabs are thrown in between, for good measure
    data = %q{
      Match host 		 foo,*.baz.com
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_equal 1234, config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_quoted_hosts_condition
    data = %q{
      Match host "foo,*.baz.com"
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_equal 1234, config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_equal_signed_hosts_condition
    data = %q{
      Match host=foo,*.baz.com
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_equal 1234, config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_quoted_equal_signed_hosts_condition
    data = %q{
      Match host="foo,*.baz.com"
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_equal 1234, config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_whitespace_separated_equal_signed_hosts_condition
    data = %q{
      Match host = foo,*.baz.com
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_equal 1234, config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_equal 1234, config['port']
    end
  end

  def test_load_with_match_block_with_multi_equal_signed_hosts_condition
    data = %q{
      Match host==foo,*.baz.com
        Port 1234
        Compression no
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "foo")
      assert_nil config['port']
    end
  end

  def test_load_with_multiple_hosts_criteria
    data = %q{
      Match host *.baz.com host !bar.baz.com
        Port 1234
    }
    with_config_from_data data do |f|
      config = Net::SSH::Config.load(f, "bar2")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bbaz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "bar.baz.com")
      assert_nil config['port']
      config = Net::SSH::Config.load(f, "meh.baz.com")
      assert_equal 1234, config['port']
    end
  end

  private

  def with_home_env(value,&block)
    env_home_before = ENV['HOME']
    begin
      ENV['HOME'] = value
      yield
    ensure
      ENV['HOME'] = env_home_before
    end
  end

  def config(name)
    "test/configs/#{name}"
  end

  def with_config_from_data(data, &block)
    Tempfile.open('config') do |f|
      f.write(data)
      f.close
      yield(f.path)
    end
  end
end
