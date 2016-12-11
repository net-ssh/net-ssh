source 'https://rubygems.org'

# Specify your gem's dependencies in mygem.gemspec
gemspec

if !Gem.win_platform? && RUBY_ENGINE == "mri"
  gem 'byebug', group: [:development, :test]
end

if ENV["CI"]
  gem 'codecov', require: false, group: :test
  gem 'simplecov', require: false, group: :test
end
