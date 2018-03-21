require_relative 'common'
require 'net/ssh'

# environment: see playbook for full details.
#  1. cert files: /etc/ssh/users_ca and /etc/ssh/users_ca.pub and
#  2. /etc/ssh/sshd_config: TrustedUserCAKeys /etc/ssh/users_ca.pub

unless ENV['NET_SSH_NO_ED25519']

  class TestCertUserAuth < NetSSHTest
    include IntegrationTestHelpers
  
    def test_ed25519_with_cert
      Dir.mktmpdir do |dir|
        sh "rm -rf #{dir}/id_rsa_ed25519 #{dir}/id_rsa_ed25519.pub"
        sh "ssh-keygen -q -f #{dir}/id_rsa_ed25519 -t ed25519 -N ''"
        sign_user_key('net_ssh_1',"#{dir}/id_rsa_ed25519.pub")
  
        # sshopts = '-vvvv -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'
        # sh "ssh -i #{dir}/id_rsa_ed25519 #{sshopts} net_ssh_1@localhost echo 'hello'"
  
        ret = Net::SSH.start("localhost", "net_ssh_1", keys: "#{dir}/id_rsa_ed25519") do |ssh|
          ssh.exec! 'echo "hello from:$USER"'
        end
        assert_equal "hello from:net_ssh_1\n", ret
      end
    end
  end

end
