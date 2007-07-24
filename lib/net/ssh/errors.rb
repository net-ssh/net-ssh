module Net; module SSH
  class Exception < ::RuntimeError; end

  class AuthenticationFailed < Exception; end
end; end