module Net; module SSH
  class Exception < ::RuntimeError; end

  class AuthenticationFailed < Exception; end

  class Disconnect < Exception; end
end; end