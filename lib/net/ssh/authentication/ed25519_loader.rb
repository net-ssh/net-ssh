module Net; module SSH; module Authentication

# Loads ED25519 support which requires optinal dependecies like
# rbnacl-libsodium, rbnacl, bcrypt_pbkdf
module ED25519Loader

begin
  require 'net/ssh/authentication/ed25519'
  LOADED = true
  ERROR = nil
rescue LoadError => e
  ERROR = e
  LOADED = false
end

def self.raiseUnlessLoaded(message)
  raise NotImplementedError, "#{message} -- see #{ERROR}" unless LOADED
end

end
end; end; end