#
# Also in your terminal environment run:
#   $ export LANG=en_US.UTF-8
#   $ export LANGUAGE=en_US.UTF-8
#   $ export LC_ALL=en_US.UTF-8

require "rubygems"
require "rake"
require "rake/clean"
require "bundler/gem_tasks"

begin
  require "rdoc/task"
rescue LoadError
  # rdoc is no longer a default gem as of Ruby 4.0; the rest of the Rakefile works without it.
end

desc "When releasing make sure NET_SSH_BUILDGEM_SIGNED is set"
task :check_NET_SSH_BUILDGEM_SIGNED do
  raise "NET_SSH_BUILDGEM_SIGNED should be set to release" unless ENV['NET_SSH_BUILDGEM_SIGNED']
end

Rake::Task[:release].enhance [:check_NET_SSH_BUILDGEM_SIGNED]
Rake::Task[:release].prerequisites.unshift(:check_NET_SSH_BUILDGEM_SIGNED)

task default: ["build"]
CLEAN.include ['pkg', 'rdoc']
name = "net-ssh"

require_relative "lib/net/ssh/version"
require_relative "rakelib/changelog"
version = Net::SSH::Version::CURRENT

extra_files = %w[LICENSE.txt THANKS.txt CHANGES.txt]
if defined?(RDoc::Task)
  RDoc::Task.new do |rdoc|
    rdoc.rdoc_dir = "rdoc"
    rdoc.title = "#{name} #{version}"
    rdoc.generator = 'hanna' # gem install hanna-nouveau
    rdoc.main = 'README.md'
    rdoc.rdoc_files.include("README*")
    rdoc.rdoc_files.include("bin/*.rb")
    rdoc.rdoc_files.include("lib/**/*.rb")
    extra_files.each { |file|
      rdoc.rdoc_files.include(file) if File.exist?(file)
    }
  end
end

namespace :cert do
  desc "Update public cert from private - only run if public is expired"
  task :update_public_when_expired do
    require 'openssl'
    require 'time'
    raw = File.read "net-ssh-public_cert.pem"
    certificate = OpenSSL::X509::Certificate.new raw
    raise Exception, "Not yet expired: #{certificate.not_after}" unless certificate.not_after < Time.now

    sh "gem cert --build netssh@solutious.com --days 365*5 --private-key /mnt/gem/net-ssh-private_key.pem"
    sh "mv gem-public_cert.pem net-ssh-public_cert.pem"
    sh "gem cert --add net-ssh-public_cert.pem"
  end
end

def change_version(&block)
  version_file = 'lib/net/ssh/version.rb'
  require_relative version_file
  pre = Net::SSH::Version::PRE
  tiny = Net::SSH::Version::TINY
  result = block[pre: pre, tiny: Net::SSH::Version::TINY]
  raise ArgumentError, "Version change logic should always return a pre" unless result.key?(:pre)

  new_pre = result[:pre]
  new_tiny = result[:tiny] || tiny
  found = { pre: false, tiny: false }
  File.open("#{version_file}.new", "w") do |f|
    File.readlines(version_file).each do |line|
      match =
        if pre.nil?
          /^(\s+PRE\s+=\s+)nil(\s*)$/.match(line)
        else
          /^(\s+PRE\s+=\s+")#{pre}("\s*)$/.match(line)
        end
      if match
        prefix = match[1]
        postfix = match[2]
        prefix.delete_suffix!('"')
        postfix.delete_prefix!('"')
        new_line = "#{prefix}#{new_pre.inspect}#{postfix}"
        puts "Changing:\n  - #{line}  + #{new_line}"
        line = new_line
        found[:pre] = true
      end

      if new_tiny != tiny
        match = /^(\s+TINY\s+=\s+)#{tiny}(\s*)$/.match(line)
        if match
          prefix = match[1]
          postfix = match[2]
          new_line = "#{prefix}#{new_tiny}#{postfix}"
          puts "Changing:\n  - #{line}  + #{new_line}"
          line = new_line
          found[:tiny] = true
        end
      end

      f.write(line)
    end
    raise ArgumentError, "Cound not find line: PRE = \"#{pre}\" in #{version_file}" unless found[:pre]
    raise ArgumentError, "Cound not find line: TINY = \"#{tiny}\" in #{version_file}" unless found[:tiny] || new_tiny == tiny
  end

  begin
    heading = Changelog.heading(Net::SSH::Version::MAJOR, Net::SSH::Version::MINOR, new_tiny, new_pre)
    section = Changelog.new(__dir__).release(heading)
  rescue StandardError
    FileUtils.rm_f "#{version_file}.new"
    raise
  end
  puts section ? "Added to CHANGES.txt:\n#{section}" : "Nothing to release for a pre-release, CHANGES.txt unchanged"

  FileUtils.mv version_file, "#{version_file}.old"
  FileUtils.mv "#{version_file}.new", version_file
end

namespace :vbump do
  desc "Final release"
  task :final do
    change_version do |pre:, tiny:|
      _ = tiny
      if pre.nil?
        { tiny: tiny + 1, pre: nil }
      else
        raise ArgumentError, "Unexpected pre: #{pre}" if pre.nil?

        { pre: nil }
      end
    end
  end

  desc "Increment prerelease"
  task :pre, [:type] do |_t, args|
    change_version do |pre:, tiny:|
      puts " PRE => #{pre.inspect}"
      match = /^([a-z]+)(\d+)/.match(pre)
      raise ArgumentError, "Unexpected pre: #{pre}" if match.nil? && args[:type].nil?

      if match.nil? || (!args[:type].nil? && args[:type] != match[1])
        if pre.nil?
          { pre: "#{args[:type]}1", tiny: tiny + 1 }
        else
          { pre: "#{args[:type]}1" }
        end
      else
        { pre: "#{match[1]}#{match[2].to_i + 1}" }
      end
    end
  end
end

namespace :changelog do
  changelog = Changelog.new(__dir__)

  desc "Validate the fragments in changelog.d/"
  task :check do
    count = changelog.check.size
    puts "#{count} valid changelog fragment#{'s' unless count == 1}"
  rescue Changelog::Error => e
    abort e.message
  end

  desc "Print the CHANGES.txt section the next version bump would write"
  task :preview, [:heading] do |_t, args|
    puts changelog.section(args[:heading] || "Unreleased") || "Nothing to release"
  rescue Changelog::Error => e
    abort e.message
  end

  desc "Create a fragment: rake \"changelog:new[1234,change,Text of the entry]\""
  task :new, [:number, :type] do |_t, args|
    abort "Usage: rake \"changelog:new[<PR number>,<#{Changelog::TYPES.keys.join('|')}>,<text>]\"" unless args[:number] && args[:type]
    # Rake splits arguments on commas and strips the spaces around them, so take the text from the raw task string.
    raw = Rake.application.top_level_tasks.find { |t| t.start_with?("changelog:new[") }
    text = raw&.[](/\A[^\[]*\[[^,]*,[^,]*,\s*(.*)\]\z/m, 1) || args.extras.join(", ")
    puts "Created #{changelog.new_fragment(args[:number], args[:type], text)}"
  rescue Changelog::Error => e
    abort e.message
  end

  desc "Write the fragments to CHANGES.txt under a heading, e.g. rake \"changelog:release[7.3.4]\" (vbump does this)"
  task :release, [:heading] do |_t, args|
    abort "Usage: rake \"changelog:release[<version heading>]\"" unless args[:heading]
    puts changelog.release(args[:heading]) || "Nothing to release"
  rescue Changelog::Error => e
    abort e.message
  end
end

namespace :rdoc do
  desc "Update gh-pages branch"
  task :publish do
    # copy/checkout
    rm_rf "/tmp/net-ssh-rdoc"
    rm_rf "/tmp/net-ssh-gh-pages"
    cp_r "./rdoc", "/tmp/net-ssh-rdoc"
    mkdir "/tmp/net-ssh-gh-pages"
    Dir.chdir "/tmp/net-ssh-gh-pages" do
      sh "git clone --branch gh-pages --single-branch https://github.com/net-ssh/net-ssh"
      rm_rf "/tmp/net-ssh-gh-pages/net-ssh/*"
    end
    # update
    sh "cp -rf ./rdoc/* /tmp/net-ssh-gh-pages/net-ssh/"
    Dir.chdir "/tmp/net-ssh-gh-pages/net-ssh" do
      sh "git add -A ."
      sh "git commit -m \"Update docs\""
    end
    # publish
    Dir.chdir "/tmp/net-ssh-gh-pages/net-ssh" do
      sh "git push origin gh-pages"
    end
  end
end

require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs = ["lib", "test"]
  t.libs << "test/integration" if ENV['NET_SSH_RUN_INTEGRATION_TESTS']
  t.libs << "test/win_integration" if ENV['NET_SSH_RUN_WIN_INTEGRATION_TESTS']
  test_files = FileList['test/**/test_*.rb']
  test_files -= FileList['test/integration/**/test_*.rb'] unless ENV['NET_SSH_RUN_INTEGRATION_TESTS']
  test_files -= FileList['test/win_integration/**/test_*.rb'] unless ENV['NET_SSH_RUN_WIN_INTEGRATION_TESTS']
  test_files -= FileList['test/manual/test_*.rb']
  test_files -= FileList['test/test_pageant.rb']
  test_files -= FileList['test/test/**/test_*.rb']
  t.test_files = test_files
end

# We need to enable the OpenSSL 3.0 legacy providers for our test suite
require 'openssl'
ENV['OPENSSL_CONF'] = 'test/openssl3.conf' if OpenSSL::OPENSSL_LIBRARY_VERSION.start_with? "OpenSSL 3"

desc "Run tests of Net::SSH:Test"
Rake::TestTask.new do |t|
  t.name = "test_test"
  # we need to run test/test separatedly as it hacks io + other modules
  t.libs = ["lib", "test"]
  test_files = FileList['test/test/**/test_*.rb']
  t.test_files = test_files
end
