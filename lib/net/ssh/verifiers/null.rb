module Net; module SSH; module Verifiers

  # The Null host key verifier simply allows every key it sees, without
  # bothering to verify. This is simple, but is not particularly secure.
  class Null
    def verify(arguments)
      true
    end
  end

end; end; end