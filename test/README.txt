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
