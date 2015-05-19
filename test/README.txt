RUNNING TESTS

Run the test suite from the net-ssh directory with the following command:

     ruby -Ilib -Itest test/test_all.rb

Run a single test file like this:

     ruby -Ilib -Itest test/transport/test_server_version.rb

EXPECTED RESULTS

     https://travis-ci.org/net-ssh/net-ssh/

INTEGRATION TESTS

     brew install ansible ; ansible-galaxy install rvm_io.rvm1-ruby ; vagrant up ; vagrant ssh
     cd /net-ssh ; rake integration-test

PORT FORWARDING TESTS

     ruby -Ilib -Itest -rrubygems test/manual/test_forward.rb

test_forward.rb must be run separately from the test suite because
it requires authorizing your public SSH keys on you localhost.

If you already have keys you can do this:

     cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

If you don't have keys see:

     http://kimmo.suominen.com/docs/ssh/#ssh-keygen

You should now be able to login to your localhost with out
bring prompted for a password:

     ssh localhost

-Delano
