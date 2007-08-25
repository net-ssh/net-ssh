require 'openssl'

require 'net/ssh/errors'
require 'net/ssh/transport/algorithms'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex'

module Net; module SSH; module Test

  class Kex
    include Net::SSH::Transport::Constants

    def initialize(algorithms, connection, data)
      @connection = connection
    end

    def exchange_keys
      result = Net::SSH::Buffer.from(:byte, NEWKEYS)
      @connection.send_message(result)

      buffer = @connection.next_message
      raise Net::SSH::Exception, "expected NEWKEYS" unless buffer.type == NEWKEYS

      { :session_id        => "abc-xyz",
        :server_key        => OpenSSL::PKey::RSA.new(32),
        :shared_secret     => OpenSSL::BN.new("1234567890", 10),
        :hashing_algorithm => OpenSSL::Digest::SHA1 }
    end
  end

end; end; end

Net::SSH::Transport::Algorithms::ALGORITHMS[:kex] << "test"
Net::SSH::Transport::Kex::MAP["test"] = Net::SSH::Test::Kex
