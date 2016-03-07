# coding: UTF-8
#
# Also in your terminal environment run:
#   $ export LANG=en_US.UTF-8
#   $ export LANGUAGE=en_US.UTF-8
#   $ export LC_ALL=en_US.UTF-8

require "rubygems"
require "rake"
require "rake/clean"
if RUBY_VERSION >= '1.9.0'
require "rdoc/task"

task :default => ["build"]
CLEAN.include [ 'pkg', 'rdoc' ]
name = "net-ssh"

$:.unshift File.join(File.dirname(__FILE__), 'lib')
require "net/ssh"
version = Net::SSH::Version::CURRENT

begin
  require "jeweler"
  Jeweler::Tasks.new do |s|
    s.version = version
    s.name = name
    s.rubyforge_project = s.name
    s.summary = "Net::SSH: a pure-Ruby implementation of the SSH2 client protocol."
    s.description = s.summary + " It allows you to write programs that invoke and interact with processes on remote servers, via SSH2."
    s.email = "net-ssh@solutious.com"
    s.homepage = "https://github.com/net-ssh/net-ssh"
    s.authors = ["Jamis Buck", "Delano Mandelbaum", "Miklós Fazekas"]
    s.required_ruby_version = '>= 2.0'

    # Note: this is run at package time not install time so if you are
    # running on jruby, you need to install jruby-pageant manually.
    if RUBY_PLATFORM == "java"
      s.add_dependency 'jruby-pageant', ">=1.1.1"
    end

    s.add_development_dependency 'test-unit'
    s.add_development_dependency 'mocha'

    s.license = "MIT"

    unless ENV['NET_SSH_NOKEY']
      signing_key = File.join('/mnt/gem/', 'net-ssh-private_key.pem')
      s.signing_key = File.join('/mnt/gem/', 'net-ssh-private_key.pem')
      s.cert_chain  = ['net-ssh-public_cert.pem']
      unless (Rake.application.top_level_tasks & ['build','install']).empty?
        raise "No key found at #{signing_key} for signing, use rake <taskname> NET_SSH_NOKEY=1 to build without key" unless File.exist?(signing_key)
      end
    end
  end
  Jeweler::RubygemsDotOrgTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

extra_files = %w[LICENSE.txt THANKS.txt CHANGES.txt ]
RDoc::Task.new do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.title = "#{name} #{version}"
  rdoc.generator = 'hanna' # gem install hanna-nouveau
  rdoc.main = 'README.rdoc'
  rdoc.rdoc_files.include("README*")
  rdoc.rdoc_files.include("bin/*.rb")
  rdoc.rdoc_files.include("lib/**/*.rb")
  extra_files.each { |file|
    rdoc.rdoc_files.include(file) if File.exists?(file)
  }
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
  if ENV['NET_SSH_RUN_INTEGRATION_TESTS']
    t.libs = ["lib","test","test/integration"]
  else
    t.libs = ["lib", "test"]
  end
end

Rake::TestTask.new(:'integration-test') do |t|
  t.libs = ["lib", "test/integration"]
  t.pattern = 'test/integration/test_*.rb'
end
