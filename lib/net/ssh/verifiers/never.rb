module Net
  module SSH
    module Verifiers
      # This host key verifier simply allows every key it sees, without
      # any verification. This is simple, but very insecure because it
      # exposes you to MiTM attacks. It does not read the known hosts files,
      # so it accepts keys marked @revoked as well.
      class Never
        # Returns true.
        def verify(arguments)
          true
        end

        def verify_signature(&block)
          true
        end
      end
    end
  end
end
