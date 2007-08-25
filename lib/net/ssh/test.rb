require 'net/ssh/transport/session'
require 'net/ssh/connection/session'
require 'net/ssh/test/kex'
require 'net/ssh/test/socket'

module Net; module SSH
  
  module Test
    def story
      yield socket.script
    end

    def socket(options={})
      @socket ||= Net::SSH::Test::Socket.new
    end

    def connection(options={})
      @connection ||= Net::SSH::Connection::Session.new(transport(options), options)
    end

    def transport(options={})
      @transport ||= Net::SSH::Transport::Session.new(options[:host] || "localhost", options.merge(:kex => "test", :host_key => "ssh-rsa", :paranoid => false, :proxy => socket(options)))
    end

    def assert_script
      raise "there is no script to be processed" if socket.script.events.empty?
      yield
      assert socket.script.events.empty?, "there should not be any remaining scripted events, but there are still #{socket.script.events.length} pending"
    end
  end

end; end