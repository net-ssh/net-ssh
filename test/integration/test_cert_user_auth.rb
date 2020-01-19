require_relative 'common'
require 'net/ssh'

# environment: see playbook for full details.
#  1. cert files: /etc/ssh/users_ca and /etc/ssh/users_ca.pub and
#  2. /etc/ssh/sshd_config: TrustedUserCAKeys /etc/ssh/users_ca.pub

unless ENV['NET_SSH_NO_ED25519']

  class TestCertUserAuth < NetSSHTest
    include IntegrationTestHelpers

    def test_ed25519_with_implicit_cert
      Dir.mktmpdir do |dir|
        sh "rm -rf #{dir}/id_rsa_ed25519 #{dir}/id_rsa_ed25519.pub"
        sh "ssh-keygen -q -f #{dir}/id_rsa_ed25519 -t ed25519 -N ''"
        sign_user_key('net_ssh_1',"#{dir}/id_rsa_ed25519.pub")

        ret = Net::SSH.start("localhost", "net_ssh_1", keys: "#{dir}/id_rsa_ed25519") do |ssh|
          ssh.exec! 'echo "hello from:$USER"'
        end
        assert_equal "hello from:net_ssh_1\n", ret
      end
    end

    def test_ed25519_with_explicit_cert
      Dir.mktmpdir do |dir|
        sh "rm -rf #{dir}/id_rsa_ed25519 #{dir}/id_rsa_ed25519.pub"
        sh "ssh-keygen -q -f #{dir}/id_rsa_ed25519 -t ed25519 -N ''"
        sign_user_key('net_ssh_1',"#{dir}/id_rsa_ed25519.pub")
        sh "mv #{dir}/id_rsa_ed25519-cert.pub #{dir}/cert"

        ret = Net::SSH.start("localhost", "net_ssh_1", keys: "#{dir}/id_rsa_ed25519", keycerts: "#{dir}/cert") do |ssh|
          ssh.exec! 'echo "hello from:$USER"'
        end
        assert_equal "hello from:net_ssh_1\n", ret
      end
    end

    def test_ed25519_with_cert_in_agent
      Dir.mktmpdir do |dir|
        with_agent do
          sh "rm -rf #{dir}/id_rsa_ed25519 #{dir}/id_rsa_ed25519.pub"
          sh "ssh-keygen -q -f #{dir}/id_rsa_ed25519 -t ed25519 -N 'pwd'"
          sign_user_key('net_ssh_1',"#{dir}/id_rsa_ed25519.pub")
          ssh_add("#{dir}/id_rsa_ed25519", "pwd")
          sh "rm -rf #{dir}/id_rsa_ed25519 #{dir}/id_rsa_ed25519.pub #{dir}/id_rsa_ed25519-cert.pub"

          ret = Net::SSH.start("localhost", "net_ssh_1") do |ssh|
            ssh.exec! 'echo "hello from:$USER"'
          end
          assert_equal "hello from:net_ssh_1\n", ret
        end
      end
    end

    def test_ed25519_with_key_in_agent_and_explicit_cert
      Dir.mktmpdir do |dir|
        with_agent do
          sh "rm -rf #{dir}/id_rsa_ed25519 #{dir}/id_rsa_ed25519.pub"
          sh "ssh-keygen -q -f #{dir}/id_rsa_ed25519 -t ed25519 -N ''"
          # add key before signing cert
          ssh_add("#{dir}/id_rsa_ed25519", "pwd")
          sign_user_key('net_ssh_1',"#{dir}/id_rsa_ed25519.pub")
          sh "rm -rf #{dir}/id_rsa_ed25519 #{dir}/id_rsa_ed25519.pub"

          ret = Net::SSH.start("localhost", "net_ssh_1", keycerts: "#{dir}/id_rsa_ed25519-cert.pub") do |ssh|
            ssh.exec! 'echo "hello from:$USER"'
          end
          assert_equal "hello from:net_ssh_1\n", ret
        end
      end
    end
  end

end
