require 'rubygems'
require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'
require 'rake/contrib/sshpublisher'

require "./lib/net/ssh/version"

PACKAGE_NAME = "net-ssh"
PACKAGE_VERSION = Net::SSH::Version::STRING
PACKAGE_VERSION << ".#{ENV['BUILD']}" if ENV['BUILD']

SOURCE_FILES = FileList.new do |fl|
  [ "examples", "lib", "test" ].each do |dir|
    fl.include "#{dir}/**/*"
  end
  fl.include "Rakefile"
end

PACKAGE_FILES = FileList.new do |fl|
  [ "api", "doc" ].each do |dir|
    fl.include "#{dir}/**/*"
  end
  fl.include "NEWS", "LICENSE", "TODO", "#{PACKAGE_NAME}.gemspec"
  fl.include "README", "THANKS", "setup.rb"
  fl.include SOURCE_FILES
end

Gem.manage_gems

def can_require( file )
  begin
    require file
    return true
  rescue LoadError
    return false
  end
end

desc "Default task"
task :default => [ :test ]

desc "Build documentation"
task :doc => [ :rdoc, :manual ]

task :rdoc => SOURCE_FILES

desc "Clean generated files"
task :clean do
  rm_rf "coverage"
  rm_rf "pkg"
  rm_rf "api"
end

desc "Generate the manual"
task :manual => %w(doc/out/index.html)

file "doc/out/index.html" => %w(doc/build.rb doc/styles.css) + Dir["doc/templates/*.erb"] + Dir["doc/faq/*.txt"] do
  rm_rf "doc/out"
  ruby "doc/build.rb"
end

Rake::TestTask.new do |t|
  t.test_files = Dir.glob("test/**/test_*.rb")
  t.verbose = true
end

desc "Build a code coverage report"
task :coverage do
  files = Dir.glob("test/**/test_*.rb").join(" ")
  sh "rcov -o coverage #{files}"
end

desc "Prepackage warnings and reminders"
task :prepackage do
  unless ENV["OK"] == "yes"
    puts "========================================================="
    puts "Please check that the following files have been updated"
    puts "in preparation for this release:"
    puts
    puts "  NEWS (with latest release notes)"
    puts "  lib/net/ssh/version.rb (with current version number)"
    puts "  doc/manual/manual.yml (with latest manual changes)"
    puts
    puts "  http://rpa-base.rubyforge.org/wiki/wiki.cgi?DeveloperChecklist"
    puts "  http://rpa-base.rubyforge.org/wiki/wiki.cgi?GoodAPIDesign"
    puts "  http://rpa-base.rubyforge.org/wiki/wiki.cgi?GoodPractices"
    puts
    puts "  svn copy http://svn.jamisbuck.org/net-ssh/trunk \\"
    puts "           http://svn.jamisbuck.org/net-ssh/tags/v#{Net::SSH::Version::MAJOR}_#{Net::SSH::Version::MINOR}_#{Net::SSH::Version::TINY} \\"
    puts "           -m \"Tagging the #{Net::SSH::Version::STRING} release\""
    puts
    puts "If you are sure these have all been taken care of, re-run"
    puts "rake with 'OK=yes'."
    puts "========================================================="
    puts

    abort
  end
end

desc "Tag the current trunk with the current release version"
task :tag do
  warn "WARNING: this will tag http://svn.jamisbuck.org/net-ssh/trunk using the tag v#{Net::SSH::Version::MAJOR}_#{Net::SSH::Version::MINOR}_#{Net::SSH::Version::TINY}"
  warn "If you do not wish to continue, you have 5 seconds to cancel by pressing CTRL-C..."
  5.times { |i| print "#{5-i} "; $stdout.flush; sleep 1 }
  system "svn copy http://svn.jamisbuck.org/net-ssh/trunk http://svn.jamisbuck.org/net-ssh/tags/v#{Net::SSH::Version::MAJOR}_#{Net::SSH::Version::MINOR}_#{Net::SSH::Version::TINY} -m \"Tagging the #{Net::SSH::Version::STRING} release\""
end

package_name = "#{PACKAGE_NAME}-#{PACKAGE_VERSION}"
package_dir = "pkg"
package_dir_path = "#{package_dir}/#{package_name}"

gz_file = "#{package_name}.tar.gz"
bz2_file = "#{package_name}.tar.bz2"
zip_file = "#{package_name}.zip"
gem_file = "#{package_name}.gem"

task :gzip => SOURCE_FILES + [ :doc, "#{package_dir}/#{gz_file}" ]
task :bzip => SOURCE_FILES + [ :doc, "#{package_dir}/#{bz2_file}" ]
task :zip  => SOURCE_FILES + [ :doc, "#{package_dir}/#{zip_file}" ]
task :gem  => SOURCE_FILES + [ "#{package_dir}/#{gem_file}" ]

desc "Build all packages"
task :package => [ :prepackage, :test, :gzip, :bzip, :zip, :gem ]

directory package_dir

file package_dir_path do
  mkdir_p package_dir_path rescue nil
  PACKAGE_FILES.each do |fn|
    f = File.join( package_dir_path, fn )
    if File.directory?( fn )
      mkdir_p f unless File.exist?( f )
    else
      dir = File.dirname( f )
      mkdir_p dir unless File.exist?( dir )
      rm_f f
      safe_ln fn, f
    end
  end
end

file "#{package_dir}/#{zip_file}" => package_dir_path do
  rm_f "#{package_dir}/#{zip_file}"
  FileUtils.chdir package_dir do
    sh %{zip -r #{zip_file} #{package_name}}
  end
end

file "#{package_dir}/#{gz_file}" => package_dir_path do
  rm_f "#{package_dir}/#{gz_file}"
  FileUtils.chdir package_dir do
    sh %{tar czvf #{gz_file} #{package_name}}
  end
end

file "#{package_dir}/#{bz2_file}" => package_dir_path do
  rm_f "#{package_dir}/#{bz2_file}"
  FileUtils.chdir package_dir do
    sh %{tar cjvf #{bz2_file} #{package_name}}
  end
end

file "#{package_dir}/#{gem_file}" => package_dir do
  spec = eval(File.read(PACKAGE_NAME+".gemspec"))
  Gem::Builder.new(spec).build
  mv gem_file, "#{package_dir}/#{gem_file}"
end

rdoc_dir = "api"

desc "Build the RDoc API documentation"
task :rdoc => :rdoc_core do
  img_dir = File.join( rdoc_dir, "files", "doc", "images" )
  mkdir_p img_dir
  Dir["doc/images/*"].reject { |i| File.directory?(i) }.each { |f|
    cp f, img_dir
  }
end

Rake::RDocTask.new( :rdoc_core ) do |rdoc|
  rdoc.rdoc_dir = rdoc_dir
  rdoc.title    = "Net::SSH -- An SSH client in, and for, Ruby"
  rdoc.options += %w(--line-numbers --inline-source --main README)
  #rdoc.rdoc_files.include 'README'
  rdoc.rdoc_files.include 'lib/**/*.rb'

  if can_require( "rdoc/generators/template/html/jamis" )
    rdoc.template = "jamis"
  end
end

desc "Publish the user's manual"
task :pubman => [ :manual ] do
  Rake::SshDirPublisher.new(
    "minam@rubyforge.org",
    "/var/www/gforge-projects/net-ssh",
    "doc/manual-html" ).upload
end

desc "Publish the API documentation"
task :pubrdoc => [ :rdoc ] do
  Rake::SshDirPublisher.new(
    "minam@rubyforge.org",
    "/var/www/gforge-projects/net-ssh/api",
    "api" ).upload
end

desc "Publish the documentation"
task :pubdoc => [:pubrdoc, :pubman]

desc "Start an IRB session with the dev load-path preloaded"
task :irb do
  system "irb -Ilib -rnet/ssh"
end
