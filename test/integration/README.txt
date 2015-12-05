# Integration tests with vagrant

Requirements:

* Vagrant (https://www.vagrantup.com/)
* Ansible (http://docs.ansible.com/intro_installation.html)

Setup:

    ansible-galaxy install rvm_io.rvm1-ruby
    vagrant up ; vagrant ssh
    rake test

# TODO

* get it running on ci (probalby needs docker)
* could not get gem install jeweler to work