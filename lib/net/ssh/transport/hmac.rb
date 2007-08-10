require 'net/ssh/transport/hmac/md5'
require 'net/ssh/transport/hmac/md5_96'
require 'net/ssh/transport/hmac/sha1'
require 'net/ssh/transport/hmac/sha1_96'
require 'net/ssh/transport/hmac/none'

module Net::SSH::Transport::HMAC
  def self.get(name, key="")
    impl = find(name) or raise IndexError, "hmac not found: #{name.inspect}"
    impl.new(key)
  end

  def self.key_length(name)
    impl = find(name) or raise IndexError, "hmac not found: #{name.inspect}"
    impl.key_length
  end

  def self.find(name)
    case name
    when 'hmac-md5'     then MD5
    when 'hmac-md5-96'  then MD5_96
    when 'hmac-sha1'    then SHA1
    when 'hmac-sha1-96' then SHA1_96
    when 'none'         then None
    else nil
    end
  end
end