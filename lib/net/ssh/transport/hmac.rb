require 'net/ssh/fips'
require 'net/ssh/transport/key_expander'
require 'net/ssh/transport/hmac/sha1'
require 'net/ssh/transport/hmac/sha1_96'
require 'net/ssh/transport/hmac/sha2_256'
require 'net/ssh/transport/hmac/sha2_256_96'
require 'net/ssh/transport/hmac/sha2_512'
require 'net/ssh/transport/hmac/sha2_512_96'
require 'net/ssh/transport/hmac/none'

unless Net::SSH::FIPS
  require 'net/ssh/transport/hmac/md5'
  require 'net/ssh/transport/hmac/md5_96'
  require 'net/ssh/transport/hmac/ripemd160'
end

# Implements a simple factory interface for fetching hmac implementations, or
# for finding the key lengths for hmac implementations.s
module Net::SSH::Transport::HMAC
  # The mapping of SSH hmac algorithms to their implementations
  MAP = { 'none' => None }

  # Add mappings if they are available
  MAP['hmac-md5']                   = MD5         if defined?(::Net::SSH::Transport::HMAC::MD5)
  MAP['hmac-md5-96']                = MD5_96      if defined?(::Net::SSH::Transport::HMAC::MD5_96)
  MAP['hmac-ripemd160']             = RIPEMD160   if defined?(::Net::SSH::Transport::HMAC::RIPEMD160)
  MAP['hmac-ripemd160@openssh.com'] = RIPEMD160   if defined?(::Net::SSH::Transport::HMAC::RIPEMD160)
  MAP['hmac-sha1']                  = SHA1        if defined?(::Net::SSH::Transport::HMAC::SHA1)
  MAP['hmac-sha1-96']               = SHA1_96     if defined?(::Net::SSH::Transport::HMAC::SHA1_96)
  MAP['hmac-sha2-256']              = SHA2_256    if defined?(::Net::SSH::Transport::HMAC::SHA2_256)
  MAP['hmac-sha2-256-96']           = SHA2_256_96 if defined?(::Net::SSH::Transport::HMAC::SHA2_256_96)
  MAP['hmac-sha2-512']              = SHA2_512    if defined?(::Net::SSH::Transport::HMAC::SHA2_512)
  MAP['hmac-sha2-512-96']           = SHA2_512_96 if defined?(::Net::SSH::Transport::HMAC::SHA2_512_96)

  # Retrieves a new hmac instance of the given SSH type (+name+). If +key+ is
  # given, the new instance will be initialized with that key.
  def self.get(name, key="", parameters = {})
    impl = MAP[name] or raise ArgumentError, "hmac not found: #{name.inspect}"
    impl.new(Net::SSH::Transport::KeyExpander.expand_key(impl.key_length, key, parameters))
  end

  # Retrieves the key length for the hmac of the given SSH type (+name+).
  def self.key_length(name)
    impl = MAP[name] or raise ArgumentError, "hmac not found: #{name.inspect}"
    impl.key_length
  end
end
