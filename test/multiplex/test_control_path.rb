# frozen_string_literal: true

require_relative '../common'
require 'net/ssh/multiplex/control_path'

module NetSSH
  class TestControlPath < NetSSHTest
    ALL_TOKENS = '%C|%h|%n|%p|%r|%j|%l|%L|%u|%i|%d|%k|%%'

    def setup
      Socket.stubs(:gethostname).returns('client.example.org')
      Process.stubs(:uid).returns(0)
      Etc.stubs(:getpwuid).with(0).returns(stub(name: 'root', dir: '/root'))
    end

    def expand(path, **args)
      Net::SSH::Multiplex::ControlPath.new(**{ port: 22, jump_host: '' }.merge(args)).expand(path)
    end

    # Expected values are from `ssh -G` (OpenSSH 10.0) on a host named
    # client.example.org, running as root.
    def test_tokens_match_openssh
      assert_equal '01aa8fab741d8ecc56275ca077434bd6eee44154|example.com|Example.COM|2222|bob||client.example.org|client|root|0|/root|Example.COM|%',
                   expand(ALL_TOKENS, host_arg: 'Example.COM', host: 'Example.COM', port: 2222, remote_user: 'bob')
      assert_equal '4c07e25822aaff5b99afa57d147305899417dc4b|10.0.0.5|web|22|alice||client.example.org|client|root|0|/root|web|%',
                   expand(ALL_TOKENS, host_arg: 'web', host: '10.0.0.5', remote_user: 'alice')
      assert_equal '5def6e2e49ca943a293d6abf10c1a1577dab7b43|host.example|host.example|22|dave||client.example.org|client|root|0|/root|hka|%',
                   expand(ALL_TOKENS, host_arg: 'host.example', host: 'host.example', remote_user: 'dave', host_key_alias: 'hka')
    end

    def test_proxy_jump_is_part_of_the_hash
      jump_host = Net::SSH::Multiplex::ControlPath.jump_host('jumper@jh.example:2200,u2@Last.Example:22')
      assert_equal 'Last.Example', jump_host
      assert_equal 'e418445b08b6d0138ea41fdf83ce935e444f5362|Last.Example',
                   expand('%C|%j', host_arg: 'db.internal', host: 'db.internal', remote_user: 'carol', jump_host: jump_host)
    end

    def test_jump_host_forms
      assert_equal 'h', Net::SSH::Multiplex::ControlPath.jump_host('h')
      assert_equal 'h', Net::SSH::Multiplex::ControlPath.jump_host('ssh://u@h:2')
      assert_equal '::1', Net::SSH::Multiplex::ControlPath.jump_host('u@[::1]:2')
      assert_equal '', Net::SSH::Multiplex::ControlPath.jump_host(nil)
    end

    def test_ipv6_host_is_not_lowercased_but_names_are
      assert_equal 'fe80::A', expand('%h', host_arg: 'x', host: 'fe80::A', remote_user: 'u')
      assert_equal 'host', expand('%h', host_arg: 'x', host: 'HOST', remote_user: 'u')
    end

    def test_tilde_uses_the_password_database_home
      home = ENV.fetch('HOME', nil)
      ENV['HOME'] = '/elsewhere'
      assert_equal '/root/.ssh/cm-u', expand('~/.ssh/cm-%r', host_arg: 'h', host: 'h', remote_user: 'u')
      assert_equal '/root', expand('~', host_arg: 'h', host: 'h', remote_user: 'u')
    ensure
      ENV['HOME'] = home
    end

    def test_environment_variables
      ENV['NET_SSH_TEST_CM_DIR'] = '/run/cm'
      assert_equal '/run/cm/h', expand('${NET_SSH_TEST_CM_DIR}/%h', host_arg: 'h', host: 'h', remote_user: 'u')
      assert_raises(ArgumentError) { expand('${NET_SSH_TEST_CM_UNSET}/x', host_arg: 'h', host: 'h', remote_user: 'u') }
      assert_raises(ArgumentError) { expand('${NET_SSH_TEST_CM_DIR', host_arg: 'h', host: 'h', remote_user: 'u') }
    ensure
      ENV.delete('NET_SSH_TEST_CM_DIR')
    end

    def test_percent_escapes_and_unknown_tokens
      assert_equal '%h', expand('%%h', host_arg: 'h', host: 'h', remote_user: 'u')
      assert_raises(ArgumentError) { expand('%z', host_arg: 'h', host: 'h', remote_user: 'u') }
      assert_raises(ArgumentError) { expand('trailing%', host_arg: 'h', host: 'h', remote_user: 'u') }
    end
  end
end
