require_relative 'common'
require 'fileutils'
require 'tmpdir'
require 'net/ssh'

require 'timeout'

# see Vagrantfile,playbook for env.
# we're running as net_ssh_1 user password foo
# and usually connecting to net_ssh_2 user password foo2pwd
class TestCertHostAuth < NetSSHTest
  include IntegrationTestHelpers

  def setup_ssh_env(&block)
    tmpdir do |dir|
      # create a cert, and sign the host key
      @cert = "#{dir}/ca"
      sh "rm -rf #{@cert} #{@cert}.pub"
      sh "ssh-keygen -t rsa -N '' -C 'ca@hosts.netssh' -f #{@cert}"
      FileUtils.cp "/etc/ssh/ssh_host_ecdsa_key.pub", "#{dir}/one.hosts.netssh.pub"
      Dir.chdir(dir) do
        sh "ssh-keygen -s #{@cert} -h -I one.hosts.netssh -n one.hosts.netssh #{dir}/one.hosts.netssh.pub"
        sh "ssh-keygen -L -f one.hosts.netssh-cert.pub"
      end
      signed_host_key = "/etc/ssh/ssh_host_ecdsa_key-cert.pub"
      sh "sudo cp -f #{dir}/one.hosts.netssh-cert.pub #{signed_host_key}"

      # we don't use this for signing the cert
      @badcert = "#{dir}/badca"
      sh "rm -rf #{@badcert} #{@badcert}.pub"
      sh "ssh-keygen -t rsa -N '' -C 'ca@hosts.netssh' -f #{@badcert}"

      yield(cert_pub: "#{@cert}.pub", badcert_pub: "#{@badcert}.pub", signed_host_key: signed_host_key)
    end
  end

  def test_host_should_match_when_host_key_was_signed_by_key
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:cert_pub])
        f.write("@cert-authority *.hosts.netssh #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(100) do
            ret = Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path], verbose: :debug) do |ssh|
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

  def test_with_other_pub_key_host_key_should_not_match
    Tempfile.open('cert_kh') do |f|
      setup_ssh_env do |params|
        data = File.read(params[:badcert_pub])
        f.write("@cert-authority *.hosts.netssh #{data}")
        f.close

        config_lines = ["HostCertificate #{params[:signed_host_key]}"]
        start_sshd_7_or_later(config: config_lines) do |_pid, port|
          Timeout.timeout(100) do
            sleep 0.2
            assert_raises(Net::SSH::HostKeyMismatch) do
              Net::SSH.start("one.hosts.netssh", "net_ssh_1", password: 'foopwd', port: port, verify_host_key: :always, user_known_hosts_file: [f.path], verbose: :debug) do |ssh|
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
