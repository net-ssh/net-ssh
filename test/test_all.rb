$: << '.'

Dir.chdir(File.dirname(__FILE__)) do
  test_files = Dir['**/test_*.rb'] - ['test_all.rb'] # prevent circular require
  test_files -= Dir['integration/test_*.rb'] unless ENV['NET_SSH_RUN_INTEGRATION_TESTS']
  test_files -= Dir['win_integration/test_*.rb'] unless ENV['NET_SSH_RUN_WIN_INTEGRATION_TESTS']
  test_files -= Dir['test/test_*.rb']
  test_files = test_files.reject { |f| f =~ /^manual/ }
  test_files = test_files.select { |f| f =~ Regexp.new(ENV['ONLY']) } if ENV['ONLY']
  test_files = test_files.reject { |f| f =~ Regexp.new(ENV['EXCEPT']) } if ENV['EXCEPT']
  test_files.each { |file| require(file) }
end