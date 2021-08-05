require_relative 'common'
require 'fileutils'
require 'tmpdir'
require 'byebug'
require 'net/ssh'

require 'timeout'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
# and usually connecting to net_ssh_2 user password foo2pwd
class TestCertHostAuth < NetSSHTest
  include IntegrationTestHelpers

  def setup_ssh_env(&block)
    tmpdir do |dir|
      @badcert = "#{dir}/badca"
      sh "rm -rf #{@badcert} #{@badcert}.pub"
      sh "ssh-keygen -t rsa -N '' -C 'ca@hosts.netssh' -f #{@badcert}"
       
      @cert = "#{dir}/ca"
      sh "rm -rf #{@cert} #{@cert}.pub"
      sh "ssh-keygen -t rsa -N '' -C 'ca@hosts.netssh' -f #{@cert}"
      FileUtils.cp "/etc/ssh/ssh_host_ecdsa_key.pub", "#{dir}/one.hosts.netssh.pub"
      Dir.chdir(dir) do
        sh "ssh-keygen -s #{@cert} -h -I one.hosts.netssh -n one.hosts.netssh #{dir}/one.hosts.netssh.pub"
        sh "ssh-keygen -L -f one.hosts.netssh-cert.pub"
      end
      # FileUtils.cp "#{dir}/cloud.jameshfisher.com-cert.pub", "/etc/ssh/ssh_host_ecdsa_key-cert.pub"
      sh "sudo cp -f #{dir}/one.hosts.netssh-cert.pub /etc/ssh/ssh_host_ecdsa_key-cert.pub"
      yield(cert_pub: "#{@cert}.pub", badcert_pub: "#{@badcert}.pub")
    end
  end

  def test_smoke
    config_lines = []
    config_lines.push("HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub")

    Tempfile.open('cert_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:cert_pub])
        puts "Data: #{data}"
        f.write("@cert-authority *.hosts.netssh #{data}")
        f.close
      
        start_sshd_7_or_later(config: config_lines, debug: true) do |_pid, port|
          Timeout.timeout(400) do
            # We have our own sshd, give it a chance to come up before
            # listening.
            ret = Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path], verbose: :debug) do |ssh|
              # assert_equal ssh.transport.algorithms.kex, "curve25519-sha256"
              ssh.exec! "echo 'foo'"
            end
            assert_equal "foo\n", ret
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end

  def test_failure
    config_lines = []
    config_lines.push("HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub")
    
    Tempfile.open('empty_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:badcert_pub])

        puts "Data: #{data}"
        f.write("@cert-authority *.hosts.netssh #{data}")
        f.close
      
        start_sshd_7_or_later(config: config_lines, debug: true) do |_pid, port|
          Timeout.timeout(400) do
            # We have our own sshd, give it a chance to come up before
            # listening.
            #sh "ssh net_ssh_1@one.hosts.netssh -p #{port} -o UserKnownHostsFile=#{f.path}"
            
            sleep 0.2
            assert_raises(Net::SSH::HostKeyMismatch) do
              Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path], verbose: :debug) do |ssh|
                # assert_equal ssh.transport.algorithms.kex, "curve25519-sha256"
                ssh.exec! "echo 'foo'"
              end
            end
          rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH
            sleep 0.25
            retry
          end
        end
      end
    end
  end
end
