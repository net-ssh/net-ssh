source 'https://rubygems.org'

# Specify your gem's dependencies in mygem.gemspec
gemspec

gem 'byebug', group: %i[development test] if !Gem.win_platform? && RUBY_ENGINE == "ruby"

if ENV["CI"]
  gem 'codecov', require: false, group: :test
  gem 'simplecov', require: false, group: :test
  gem 'webrick' if RUBY_VERSION.split(".")[0].to_i >= 3
end
