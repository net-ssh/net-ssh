require_relative 'common'
require 'net/ssh/buffer'
require 'net/ssh'
require 'timeout'
require 'tempfile'
require 'net/ssh/proxy/command'
require 'net/ssh/proxy/http'

require 'webrick'
require 'webrick/httpproxy'

class TestHTTPProxy < NetSSHTest
  include IntegrationTestHelpers

  def localhost
    'localhost'
  end

  def user
    'net_ssh_1'
  end

  def ssh_start_params(options)
    [localhost, user, {:keys => @key_id_rsa}.merge(options)]
  end

  def setup_ssh_env(&block)
    tmpdir do |dir|
      @key_id_rsa = "#{dir}/id_rsa"
      sh "rm -rf #{@key_id_rsa} #{@key_id_rsa}.pub"
      sh "ssh-keygen -q -f #{@key_id_rsa} -t rsa -N ''"
      set_authorized_key(user,"#{@key_id_rsa}.pub")
      yield
    end
  end

  def with_http_proxy_server(&block)
    proxy = WEBrick::HTTPProxyServer.new Port: 0
    Thread.start { proxy.start }
    begin
      yield(proxy)
    ensure
      proxy.shutdown
    end
  end

  def test_smoke
    setup_ssh_env do
      with_http_proxy_server do |http_proxy|
        msg = 'echo123'
        ret = Net::SSH.start(*ssh_start_params(:proxy => Net::SSH::Proxy::HTTP.new('localhost', http_proxy.config[:Port]))) do |ssh|
          ssh.exec! "echo \"$USER:#{msg}\""
        end
        assert_equal "net_ssh_1:#{msg}\n", ret
      end
    end
  end
end