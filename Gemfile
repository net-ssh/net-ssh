source 'https://rubygems.org'

# Note: this is run at package time not install time so if you are
# running on jruby, you need to install jruby-pageant manually.
gem 'jruby-pageant', ">=1.1.1" if RUBY_PLATFORM == "java"

gem 'rbnacl-libsodium', ">=1.0.2"
gem 'rbnacl', ">=3.1.2"
gem 'bcrypt_pbkdf', '1.0.0.alpha1' unless RUBY_PLATFORM == "java"


group :development do
  gem 'rake'
  gem 'test-unit', ">= 0.8.5"
  gem 'mocha'
  gem 'jeweler'
end
