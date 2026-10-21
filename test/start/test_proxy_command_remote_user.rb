# frozen_string_literal: true

require_relative '../common'
require 'net/ssh'
require 'net/ssh/proxy/command'
require 'tempfile'

module NetSSH
  class TestStartProxyCommandRemoteUser < NetSSHTest
    def setup
      authentication_session = mock('authentication_session')
      authentication_session.stubs(:authenticate).returns(true)
      Net::SSH::Authentication::Session.stubs(:new).returns(authentication_session)
      Net::SSH::Connection::Session.stubs(:new).returns(mock('connection_session'))
    end

    def test_percent_r_uses_positional_user
      assert_proxy_command "connect alice@example.com:22", 'alice', {}
    end

    def test_percent_r_uses_user_from_ssh_config
      with_ssh_config("Host example.com\n  User bob\n") do |config|
        assert_proxy_command "connect bob@example.com:22", nil, { config: config }
      end
    end

    def test_explicit_remote_user_wins
      with_ssh_config("Host example.com\n  User bob\n") do |config|
        assert_proxy_command "connect carol@example.com:22", 'alice', { config: config, remote_user: 'carol' }
      end
    end

    def test_percent_r_falls_back_to_local_user
      assert_proxy_command "connect #{Etc.getpwuid.name}@example.com:22", nil, {}
    end

    private

    def assert_proxy_command(expected, user, options)
      IO.expects(:popen).with(expected, "r+").raises(Errno::ENOENT)
      proxy = Net::SSH::Proxy::Command.new('connect %r@%h:%p')
      assert_raises(Net::SSH::Proxy::ConnectError) do
        Net::SSH.start('example.com', user, { config: false }.merge(options).merge(proxy: proxy))
      end
    end

    def with_ssh_config(content)
      Tempfile.create('ssh_config') do |f|
        f.write(content)
        f.close
        yield f.path
      end
    end
  end
end
