require_relative 'common'
require 'net/ssh/buffer'
require 'net/ssh'
require 'timeout'
require 'tempfile'
require 'net/ssh/proxy/command'
require 'net/ssh/proxy/jump'

class TestProxy < NetSSHTest
  include IntegrationTestHelpers

  def localhost
    'localhost'
  end

  def user
    'net_ssh_1'
  end

  def ssh_start_params(options)
    [localhost,user, { keys: @key_id_rsa }.merge(options)]
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

  def setup_gateway(&block)
    gwhost = "gateway.netssh"
    gwuser = 'net_ssh_2'
    tmpdir do |dir|
      @gwkey_id_rsa = "#{dir}/id_rsa"
      sh "rm -rf #{@gwkey_id_rsa} #{@gwkey_id_rsa}.pub"
      sh "ssh-keygen -q -f #{@gwkey_id_rsa} -t rsa -N ''"
      set_authorized_key(gwuser,"#{@gwkey_id_rsa}.pub")
      config = "Host #{gwhost}
                  IdentityFile #{@gwkey_id_rsa}
                  StrictHostKeyChecking no
               "
      my_config = File.expand_path("~/.ssh/config")
      File.open(my_config, 'w') { |file| file.write(config) }
      begin
        FileUtils.chmod(0o600, my_config)
        yield gwuser, gwhost
      ensure
        FileUtils.rm(my_config)
      end
    end
  end

  def test_smoke
    setup_ssh_env do
      proxy = Net::SSH::Proxy::Command.new("/bin/nc localhost 22")
      msg = 'echo123'
      ret = Net::SSH.start(*ssh_start_params(proxy: proxy)) do |ssh|
        ssh.exec! "echo \"$USER:#{msg}\""
      end
      assert_equal "net_ssh_1:#{msg}\n", ret
    end
  end

  def with_spurious_write_wakeup_emulate(rate=99,&block)
    orig_io_select = IO.method(:select)
    count = 0
    IO.singleton_class.send(:define_method, :select) do |*params|
      count += 1
      if (count % rate != 0)
        if params && params[1] && !params[1].empty?
          return [[],params[1],[]]
        end
      end
      orig_io_select.call(*params)
    end
    begin
      yield
    ensure
      IO.singleton_class.send(:define_method, :select, &orig_io_select)
    end
  end

  def test_with_rate_limit_and_spurious_wakeup
    system("sudo sh -c 'echo 4096 > /proc/sys/fs/pipe-max-size'")
    begin
      setup_ssh_env do
        proxy = Net::SSH::Proxy::Command.new("/usr/bin/pv --rate-limit 100k | /bin/nc localhost 22")
        #proxy = Net::SSH::Proxy::Command.new("/bin/nc localhost 22")
        begin
          large_msg = 'echo123' * 30000
          ok = Net::SSH.start(*ssh_start_params(proxy: proxy)) do |ssh|
            with_spurious_write_wakeup_emulate do
              ret = ssh.exec! "echo \"$USER:#{large_msg}\""
              #assert_equal "net_ssh_1:#{large_msg}\n", ret
              assert_equal "/bin/sh: Argument list too long\n", ret
              hello_count = 1000
              ret = ssh.exec! "ruby -e 'puts \"Hello\"*#{hello_count}'"
              assert_equal "Hello" * hello_count + "\n", ret
            end
            :ok
          end
        end
        assert_equal :ok, ok
      end
    ensure
      system("sudo sh -c 'echo 1048576 > /proc/sys/fs/pipe-max-size'")
    end
  end

  def test_proxy_jump_through_localhost
    setup_ssh_env do
      setup_gateway do |gwuser, gwhost|
        proxy = Net::SSH::Proxy::Jump.new("#{gwuser}@#{gwhost}")
        #puts "ssh #{user}@#{localhost} -i #{@key_id_rsa} -J #{gwuser}@#{gwhost} -vvv"
        output = Net::SSH.start(*ssh_start_params(proxy: proxy)) do |ssh|
          ssh.exec! "echo \"$USER:echo123\""
        end
        assert_equal "net_ssh_1:echo123\n", output
      end
    end
  end

  class DbgProxy
    attr_reader :io

    def initialize(origin)
      @origin = origin
    end

    def open(*args)
      @io = @origin.open(*args)
      @io
    end
  end
  def test_does_close_proxy_on_proxy_failure
    setup_ssh_env do
      proxy = DbgProxy.new(Net::SSH::Proxy::Command.new('sleep 2 && ssh -W %h:%p -o "PreferredAuthentications none" user@localhost'))
      msg = 'echo123'
      assert_raises Errno::EPIPE, Net::SSH::Proxy::ConnectError do
        Net::SSH.start(*ssh_start_params(proxy: proxy, password: 'bad', non_interactive: true, auth_methods: ['password'], verbose: :debug)) do |ssh|
          ssh.exec! "echo \"$USER:#{msg}\""
        end
      end
      assert proxy.io.nil? || proxy.io.closed?, "Process #proxy.io.pid not closed"
    end
  end
end
