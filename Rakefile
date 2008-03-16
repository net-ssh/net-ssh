if !File.exist?('Manifest.txt') || ENV['REBUILD_MANIFEST']
  source_files = FileList.new do |fl|
    [ "lib", "test" ].each do |dir|
      fl.include "#{dir}/**/*"
    end

    fl.include "History.txt", "Manifest.txt", "README.txt", "Thanks.txt"
    fl.include "Rakefile", "setup.rb"
  end

  File.open("Manifest.txt", "w") do |f|
    source_files.each do |file|
      next if File.directory?(file)
      f.puts(file)
    end
  end
end

require './lib/net/ssh/version'

require 'hoe'

version = Net::SSH::Version::STRING.dup
if ENV['SNAPSHOT'].to_i == 1
  version << "." << Time.now.utc.strftime("%Y%m%d%H%M%S")
end

Hoe.new('net-ssh', version) do |p|
  p.author         = "Jamis Buck"
  p.email          = "jamis@jamisbuck.org"
  p.summary        = "a pure-Ruby implementation of the SSH2 client protocol"
  p.url            = "http://net-ssh.rubyforge.org/ssh"
  p.need_zip       = true
  p.rubyforge_name = "net-ssh"
end
