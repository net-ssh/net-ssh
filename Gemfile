source 'https://rubygems.org'

# Specify your gem's dependencies in mygem.gemspec
gemspec

if !Gem.win_platform? && RUBY_ENGINE == "ruby"
  gem 'byebug', group: [:development, :test]
end

if (Gem::Version.new(RUBY_VERSION) <=> Gem::Version.new("2.2.6")) < 0
  gem 'rbnacl', '< 4.0'
end

if ENV["CI"]
  gem 'codecov', require: false, group: :test
  gem 'simplecov', require: false, group: :test
end
