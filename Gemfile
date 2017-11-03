source 'https://rubygems.org'

# Specify your gem's dependencies in mygem.gemspec
gemspec

ruby_semver = Gem::Version.new(RUBY_VERSION)

if !Gem.win_platform? && RUBY_ENGINE == "ruby"
  byebug_version = if ruby_semver < Gem::Version.new("2.2.0")
                     "~>9.0.6"
                   else
                     "~>9.1.0"
                   end

  gem 'byebug', byebug_version, group: [:development, :test]
end

gem 'rbnacl', '< 4.0' if ruby_semver < Gem::Version.new("2.2.6")

if ENV["CI"]
  gem 'codecov', require: false, group: :test
  gem 'simplecov', require: false, group: :test
end
