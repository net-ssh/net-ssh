require 'net/ssh/transport/hmac/abstract'

module Net::SSH::Transport::HMAC
  # The SHA-512 Encrypt-Then-Mac HMAC algorithm. This has a mac and
  # key length of 64, and uses the SHA-512 digest algorithm.
  class Aes256gcm < Abstract
    aead         true
    mac_length   16
    key_length   32
  end
end
