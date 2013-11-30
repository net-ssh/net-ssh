require 'common'
require 'net/ssh'

module NetSSH
  class TestConnection < Test::Unit::TestCase
    attr_reader :connection_session
    
    def setup
      authentication_session = mock('authentication_session')
      authentication_session.stubs(:authenticate).returns(true)
      Net::SSH::Authentication::Session.stubs(:new).returns(authentication_session)
      Net::SSH::Transport::Session.stubs(:new).returns(mock('transport_session'))
      @connection_session = mock('connection_session')
      Net::SSH::Connection::Session.expects(:new => connection_session)
    end
    
    def test_close_connection_on_exception
      @connection_session.expects(:closed?).returns(false)
      @connection_session.expects(:close).once
      
      begin
        Net::SSH.start('localhost', 'testuser') { raise "error" }
      rescue RuntimeError
        # We aren't interested in the exception
      end
    end

    def test_close_connection_on_exception_only_if_still_open
      conn_open = states('conn').starts_as(true)
      @connection_session.expects(:close).then(conn_open.is(false)).once
      @connection_session.expects(:closed?).when(conn_open.is(false)).returns(true)
      
      begin
        Net::SSH.start('localhost', 'testuser') do |ssh|
          ssh.close
          raise "error"
        end
      rescue RuntimeError
        # We aren't interested in the exception
      end
    end
  end
end

