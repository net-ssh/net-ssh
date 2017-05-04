require 'openssl'

module Net; module SSH
  # generic public key utility functions
  module PubKey
    # Return the key's fingerprint. algorithm may be either +SHA256+ or
    # +MD5+ (default). SHA256 fingerprints are in the same format
    # returned by OpenSSH's `ssh-add -l -E SHA256`, i.e.,
    # trailing base64 padding '=' characters are stripped and the
    # literal string 'SHA256:' is prepended.
    def fingerprint(algorithm='MD5')
      @fingerprint ||= {}
      @fingerprint[algorithm] ||=
        case algorithm.upcase
        when 'MD5'
          OpenSSL::Digest.hexdigest(algorithm, to_blob).scan(/../).join(":")
        when 'SHA256'
          "SHA256:#{Base64.encode64(OpenSSL::Digest.digest(algorithm, to_blob)).chomp.gsub(/=+\z/, '')}"
        else
          raise OpenSSL::Digest::DigestError, "unsupported ssh key digest #{algorithm}"
        end
    end
  end
end; end
