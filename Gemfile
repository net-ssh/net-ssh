source 'https://rubygems.org'

# Specify your gem's dependencies in mygem.gemspec
gemspec

gem "changelogd", git: "https://github.com/net-ssh/changelogd.git", tag: "v1", group: :development

gem 'byebug', group: %i[development test] if !Gem.win_platform? && RUBY_ENGINE == "ruby"

if ENV["CI"]
  gem 'codecov', require: false, group: :test
  gem 'simplecov', require: false, group: :test
end

gem 'webrick', group: %i[development test] if RUBY_VERSION.split(".")[0].to_i >= 3
