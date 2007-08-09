module Net; module SSH; module Verifiers

  # The NullHostKeyVerifier simply allows every key it sees, without
  # bothering to verify. This is simple, but is not particularly secure.
  class NullHostKeyVerifier
    def verify(arguments)
      true
    end
  end

end; end; end