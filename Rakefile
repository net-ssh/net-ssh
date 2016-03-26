# coding: UTF-8
#
# Also in your terminal environment run:
#   $ export LANG=en_US.UTF-8
#   $ export LANGUAGE=en_US.UTF-8
#   $ export LC_ALL=en_US.UTF-8

require "rubygems"
require "rake"
require "rake/clean"
require "bundler/gem_tasks"

require "rdoc/task"

task :default => ["build"]
CLEAN.include [ 'pkg', 'rdoc' ]
name = "net-ssh"

$:.unshift File.join(File.dirname(__FILE__), 'lib')
require "net/ssh"
version = Net::SSH::Version::CURRENT

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
end
