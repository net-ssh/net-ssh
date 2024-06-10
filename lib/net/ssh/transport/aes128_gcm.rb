require 'net/ssh/transport/hmac/abstract'
require 'net/ssh/transport/gcm_cipher'

module Net::SSH::Transport
  ## Implements the aes128-gcm@openssh cipher
  class AES128_GCM
    extend ::Net::SSH::Transport::GCMCipher

    ## Implicit HMAC, do need to do anything
    class ImplicitHMac < ::Net::SSH::Transport::HMAC::Abstract
      def aead
        true
      end

      def key_length
        16
      end
    end

    def implicit_mac
      ImplicitHMac.new
    end

    def algo_name
      'aes-128-gcm'
    end

    def name
      'aes128-gcm@openssh.com'
    end

    #
    # --- RFC 5647 ---
    # K_LEN       AES key length                   16 octets
    #
    def self.key_length
      16
    end
  end
end
