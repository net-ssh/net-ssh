$LOAD_PATH.unshift "#{File.dirname(__FILE__)}/../lib"

if ENV["CI"]
  unless Gem.win_platform?
    require 'simplecov'
    SimpleCov.start

    require 'codecov'
    SimpleCov.formatter = SimpleCov::Formatter::Codecov
  end
end

require 'minitest'
require 'mocha/setup'
require 'net/ssh/buffer'
require 'net/ssh/config'
require 'net/ssh/loggable'
require 'net/ssh/packet'
require 'net/ssh/transport/session'
require 'ostruct'

require 'minitest/autorun'

# clear the default files out so that tests don't get confused by existing
# SSH config files.
$_original_config_default_files = Net::SSH::Config.default_files.dup # rubocop:disable Style/GlobalVars
Net::SSH::Config.default_files.clear

# Ensures SSH_AUTH_SOCK set outside of test scenario (e.g. on dev's machine) isn't messing up test assertions
original_ssh_auth_sock, ENV['SSH_AUTH_SOCK'] = ENV['SSH_AUTH_SOCK'], nil
Minitest.after_run { ENV['SSH_AUTH_SOCK'] = original_ssh_auth_sock }

def with_restored_default_files(&block)
  act_default_files = Net::SSH::Config.default_files.dup
  begin
    Net::SSH::Config.default_files.clear
    Net::SSH::Config.default_files.concat($_original_config_default_files) # rubocop:disable Style/GlobalVars
    yield
  ensure
    Net::SSH::Config.default_files.clear
    Net::SSH::Config.default_files.concat(act_default_files)
  end
end

def P(*args)
  Net::SSH::Packet.new(Net::SSH::Buffer.from(*args))
end

class NetSSHTest < Minitest::Test
  def assert_nothing_raised(&block)
    yield
  end

  def assert_not_nil obj, msg = nil
    refute_nil obj, msg
  end
end

class MockPrompt
  def start(info)
    @info = info
    self
  end

  def ask(message, echo)
    _ask(message, @info, echo)
  end

  def success; end
end

class MockTransport < Net::SSH::Transport::Session
  class BlockVerifier
    def initialize(block)
      @block = block
    end

    def verify(data)
      @block.call(data)
    end

    def verify_signature(&block)
      yield
    end
  end

  attr_reader :host_key_verifier
  attr_accessor :host_as_string
  attr_accessor :server_version

  attr_reader :client_options
  attr_reader :server_options
  attr_reader :hints, :queue

  attr_accessor :mock_enqueue

  def initialize(options={})
    @options = options
    self.logger = options[:logger]
    self.host_as_string = "net.ssh.test,127.0.0.1"
    self.server_version = OpenStruct.new(version: "SSH-2.0-Ruby/Net::SSH::Test")
    @expectations = []
    @queue = []
    @hints = {}
    @socket = options[:socket]
    @algorithms = OpenStruct.new(session_id: "abcxyz123")
    verifier { |data| true }
  end

  def send_message(message)
    buffer = Net::SSH::Buffer.new(message.to_s)
    if @expectations.empty?
      raise "got #{message.to_s.inspect} but was not expecting anything"
    else
      block = @expectations.shift
      block.call(self, Net::SSH::Packet.new(buffer))
    end
  end

  def enqueue_message(message)
    if mock_enqueue
      send_message(message)
    else
      super
    end
  end

  def closed?
    false
  end

  def poll_message
    @queue.shift
  end

  def next_message
    @queue.shift or raise "expected a message from the server but nothing was ready to send"
  end

  def return(type, *args)
    @queue << P(:byte, type, *args)
  end

  def expect(&block)
    @expectations << block
  end

  def expect!
    expect {}
  end

  def verifier(&block)
    @host_key_verifier = BlockVerifier.new(block)
  end

  def configure_client(options)
    @client_options = options
  end

  def configure_server(options)
    @server_options = options
  end

  def hint(name, value=true)
    @hints[name] = value
  end
end
