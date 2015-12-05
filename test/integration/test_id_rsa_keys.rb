require 'common'
require 'fileutils'
require 'tmpdir'

require 'net/ssh'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
# and usually connecting to net_ssh_2 user password foo2pwd
class TestIDRSAPKeys < Test::Unit::TestCase
  include IntegrationTestHelpers

  def test_in_file_no_password
    tmpdir do |dir|
      sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
      sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N ''"
      set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")

      sshopts = '-vvvv -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
      #sh "ssh -i #{dir}/id_rsa #{sshopts} net_ssh_1@localhost echo 'hello'"

      ret = Net::SSH.start("localhost", "net_ssh_1", {keys: "#{dir}/id_rsa"}) do |ssh|
        ssh.exec! 'echo "hello from:$USER"'
      end
      assert_equal "hello from:net_ssh_1\n", ret
    end
  end


  def test_ssh_agent
    tmpdir do |dir|
      with_agent do
        sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
        sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N 'pwd123'"
        set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")
        ssh_add("#{dir}/id_rsa","pwd123")

        ret = Net::SSH.start("localhost", "net_ssh_1",verbose: :debug) do |ssh|
          ssh.exec! 'echo "hello from:$USER"'
        end
        assert_equal "hello from:net_ssh_1\n", ret
      end
    end
  end

  def test_ssh_agent_ignores_if_already_in_agent
    tmpdir do |dir|
      with_agent do
        sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
        sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N 'pwd123'"
        set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")
        ssh_add("#{dir}/id_rsa","pwd123")

        ret = Net::SSH.start("localhost", "net_ssh_1",verbose: :debug, keys: ["#{dir}/id_rsa"]) do |ssh|
          ssh.exec! 'echo "hello from:$USER"'
        end
        assert_equal "hello from:net_ssh_1\n", ret
      end
    end
  end

  def test_in_file_with_password
    tmpdir do |dir|
      sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
      sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N 'pwd12'"
      set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")

      sshopts = '-vvvv -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
      #sh "ssh -i #{dir}/id_rsa #{sshopts} net_ssh_1@localhost echo 'hello'"

      ret = Net::SSH.start("localhost", "net_ssh_1", {keys: "#{dir}/id_rsa",
        passphrase: 'pwd12', verbose: :debug}) do |ssh|
        ssh.exec! 'echo "hello from:$USER"'
      end
      assert_equal "hello from:net_ssh_1\n", ret
    end
  end

  def test_asks_for_passwords_when_read_from_memory
    tmpdir do |dir|
      sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
      sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N 'pwd12'"
      set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")
      private_key = File.read("#{dir}/id_rsa")

      options = {keys: [], key_data: [private_key]}

      key_manager = Net::SSH::Authentication::KeyManager.new(nil, options)

      Net::SSH::KeyFactory.expects(:prompt).with('Enter passphrase for :', false).returns('pwd12')
      Net::SSH.start("localhost", "net_ssh_1", options) do |ssh|
        ssh.exec! 'whoami'
      end
    end
  end
end
