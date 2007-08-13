require 'net/ssh/transport/hmac/md5'
require 'net/ssh/transport/hmac/md5_96'
require 'net/ssh/transport/hmac/sha1'
require 'net/ssh/transport/hmac/sha1_96'
require 'net/ssh/transport/hmac/none'

module Net::SSH::Transport::HMAC
  MAP = {
    'hmac-md5'     => MD5,
    'hmac-md5-96'  => MD5_96,
    'hmac-sha1'    => SHA1,
    'hmac-sha1-96' => SHA1_96,
    'none'         => None
  }

  def self.get(name, key="")
    impl = MAP[name] or raise ArgumentError, "hmac not found: #{name.inspect}"
    impl.new(key)
  end

  def self.key_length(name)
    impl = MAP[name] or raise ArgumentError, "hmac not found: #{name.inspect}"
    impl.key_length
  end
end