require 'common'
require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha1'
require 'transport/kex/test_diffie_hellman_group_exchange_sha1'

module Transport; module Kex

  class TestDiffieHellmanGroupExchangeSHA256 < TestDiffieHellmanGroupExchangeSHA1
    private

      def subject
        Net::SSH::Transport::Kex::DiffieHellmanGroupExchangeSHA256
      end

      def digest_type
        OpenSSL::Digest::SHA256
      end
  end

end; end
