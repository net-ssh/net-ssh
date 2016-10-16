source 'https://rubygems.org'

# Specify your gem's dependencies in mygem.gemspec
gemspec

unless Gem.win_platform? || RUBY_PLATFORM == "java"
  gem 'byebug', group: [:development, :test]
end
