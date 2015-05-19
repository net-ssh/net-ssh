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
    Dir.mktmpdir do |dir| dir = "/tmp/test"
      sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
      sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N ''"
      set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")

      # TODO: fix bug in net ssh which reads public key even if private key is there
      sh "mv #{dir}/id_rsa.pub #{dir}/id_rsa.pub.hidden"

      sshopts = '-vvvv -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
      #sh "ssh -i #{dir}/id_rsa #{sshopts} net_ssh_1@localhost echo 'hello'"

      ret = Net::SSH.start("localhost", "net_ssh_1", {keys: "#{dir}/id_rsa"}) do |ssh|
        ssh.exec! 'echo "hello from:$USER"'
      end
      assert_equal "hello from:net_ssh_1\n", ret
    end
  end


  def test_ssh_agent
    Dir.mktmpdir do |dir| dir = "/tmp/test"
      with_agent do
        sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
        sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N 'pwd12'"
        set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")
        ssh_add("#{dir}/id_rsa","pwd12")

        # TODO: fix bug in net ssh which reads public key even if private key is there
        sh "mv #{dir}/id_rsa.pub #{dir}/id_rsa.pub.hidden"

        ret = Net::SSH.start("localhost", "net_ssh_1",verbose: :debug) do |ssh|
          ssh.exec! 'echo "hello from:$USER"'
        end
        assert_equal "hello from:net_ssh_1\n", ret
      end
    end
  end

  def test_in_file_with_password
    Dir.mktmpdir do |dir| dir = "/tmp/test"
      sh "rm -rf #{dir}/id_rsa #{dir}/id_rsa.pub"
      sh "ssh-keygen -f #{dir}/id_rsa -t rsa -N 'pwd12'"
      set_authorized_key('net_ssh_1',"#{dir}/id_rsa.pub")

      # TODO: fix bug in net ssh which reads public key even if private key is there
      sh "mv #{dir}/id_rsa.pub #{dir}/id_rsa.pub.hidden"

      sshopts = '-vvvv -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
      #sh "ssh -i #{dir}/id_rsa #{sshopts} net_ssh_1@localhost echo 'hello'"

      ret = Net::SSH.start("localhost", "net_ssh_1", {keys: "#{dir}/id_rsa",
        passphrase: 'pwd12', verbose: :debug}) do |ssh|
        ssh.exec! 'echo "hello from:$USER"'
      end
      assert_equal "hello from:net_ssh_1\n", ret
    end
  end
end
