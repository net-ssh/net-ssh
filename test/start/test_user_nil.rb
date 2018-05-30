require 'common'
require 'net/ssh'

module NetSSH
  class TestStartUserNil < NetSSHTest
    def setup
      @authentication_session = mock('authentication_session')
      Net::SSH::Authentication::Session.stubs(:new).returns(@authentication_session)
      Net::SSH::Transport::Session.stubs(:new).returns(mock('transport_session'))
      Net::SSH::Connection::Session.stubs(:new).returns(mock('connection_session'))
    end

    def test_start_should_accept_nil_user
      @authentication_session.stubs(:authenticate).returns(true)
      assert_nothing_raised do
        Net::SSH.start('localhost')
      end
    end

    def test_start_should_use_default_user_when_nil
      @authentication_session.stubs(:authenticate).with() {|_next_service, user, _password| user == Etc.getlogin }.returns(true)
      assert_nothing_raised do
        Net::SSH.start('localhost', nil, config: false)
      end
    end
  end
end
