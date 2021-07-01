require_relative '../../common'
require_relative './test_diffie_hellman_group14_sha1'

module Transport
  module Kex
    class TestDiffieHellmanGroup14SHA256 < TestDiffieHellmanGroup14SHA1
      def subject
        Net::SSH::Transport::Kex::DiffieHellmanGroup14SHA256
      end

      def digest_type
        OpenSSL::Digest::SHA256
      end
    end
  end
end
