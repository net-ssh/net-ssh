# Integration tests with vagrant

Requirements:

* Vagrant (https://www.vagrantup.com/)
* Ansible (http://docs.ansible.com/intro_installation.html)

Setup:

    ansible-galaxy install rvm.ruby
    vagrant up ; vagrant ssh
    rvmsudo_secure_path=1 rvmsudo rvm all do gem install bundler
    rvm all do sh -c 'rm Gemfile.lock; bundle'
    rvm all do rake test

# Debugging on travis

Logging the ssh logs might be useful:

```yml
script:
  - #NET_SSH_RUN_INTEGRATION_TESTS=1 bundle exec rake test
  - sudo tail -n 3 /var/log/auth.log
  - bundle exec ruby -Ilib:test ./test/integration/test_forward.rb -n test_client_close_should_be_handled_remote
  - sudo tail -n 60 /var/log/auth.log
  - bundle exec rubocop
```
