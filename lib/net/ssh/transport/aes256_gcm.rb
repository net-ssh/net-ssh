require 'net/ssh/transport/hmac/abstract'
require 'net/ssh/transport/gcm_cipher'

module Net::SSH::Transport
  ## Implements the aes256-gcm@openssh cipher
  class AES256_GCM
    extend ::Net::SSH::Transport::GCMCipher

    ## Implicit HMAC, do need to do anything
    class ImplicitHMac < ::Net::SSH::Transport::HMAC::Abstract
      def aead
        true
      end

      def key_length
        32
      end
    end

    def implicit_mac
      ImplicitHMac.new
    end

    def algo_name
      'aes-256-gcm'
    end

    def name
      'aes256-gcm@openssh.com'
    end

    #
    # --- RFC 5647 ---
    # K_LEN       AES key length                   32 octets
    #
    def self.key_length
      32
    end
  end
end
