source 'https://rubygems.org'

# Specify your gem's dependencies in mygem.gemspec
gemspec

gem 'byebug', group: %i[development test] if !Gem.win_platform? && RUBY_ENGINE == "ruby"

if ENV["CI"]
  gem 'codecov', require: false, group: :test
  gem 'simplecov', require: false, group: :test
  gem 'x25519', github: 'RubyCrypto/x25519', ref: '60c0f2913460c7b13b516e4e887a5517a2bd9edd'
end

gem 'webrick', group: %i[development test] if RUBY_VERSION.split(".")[0].to_i >= 3
