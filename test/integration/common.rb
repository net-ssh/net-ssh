$LOAD_PATH.unshift "#{File.dirname(__FILE__)}/../../lib"
gem "test-unit" # http://rubyforge.org/pipermail/test-unit-tracker/2009-July/000075.html
gem 'mocha'
require 'test/unit'
require 'mocha/setup'
require 'pty'
require 'expect'

module IntegrationTestHelpers
  def sh command
    puts "$ #{command}"
    res = system(command)
    status = $?
    raise "Command: #{command} failed:#{status.exitstatus}" unless res
  end

  def tmpdir(&block)
    Dir.mktmpdir do |dir|
      yield(dir)
    end
  end

  def set_authorized_key(user,pubkey)
    authorized_key = "/home/#{user}/.ssh/authorized_keys"
    sh "sudo cp #{pubkey} #{authorized_key}"
    sh "sudo chown #{user} #{authorized_key}"
    sh "sudo chmod 0744 #{authorized_key}"
  end

  def with_agent(&block)
    puts "/usr/bin/ssh-agent -c"
    agent_out = `/usr/bin/ssh-agent -c`
    agent_out.split("\n").each do |line|
      if line =~ /setenv (\S+) (\S+);/
        ENV[$1] = $2
        puts "ENV[#{$1}]=#{$2}"
      end
    end
    begin
      yield
    ensure
      sh "/usr/bin/ssh-agent -k"
    end
  end

  def ssh_add(key,password)
    command = "ssh-add #{key}"
    status = nil
    PTY.spawn(command) do |reader, writer, pid|
      begin
        reader.expect(/Enter passphrase for .*:/) { |data| puts data }
        writer.puts(password)
        until reader.eof? do
          puts reader.readline
        end
      rescue Errno::EIO => e
      end
      pid, status = Process.wait2 pid
    end
    raise "Command: #{command} failed:#{status.exitstatus}" unless status
    status.exitstatus
  end
end