require 'net/ssh/transport/kex/diffie_hellman_group14_sha1'

module Net::SSH::Transport::Kex
  # A key-exchange service implementing the "diffie-hellman-group14-sha256"
  # key-exchange algorithm.
  class DiffieHellmanGroup14SHA256 < DiffieHellmanGroup14SHA1
    def digester
      OpenSSL::Digest::SHA256
    end
  end
end
