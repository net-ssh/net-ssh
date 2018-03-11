# Systems that are running in FIPS 140-2 compliant mode cannot use certain
# cryptographic algorithms. This parameter will be set to `true` when the
# underlying system is in FIPS 140-2 compliant mode. The rescue mechanism is
# used for compatibility with legacy Ruby versions.
#
# This needs to be before ANY segment that requires cryptography that may be
# affected by FIPS mode in the underlying system.
module Net
  module SSH
    begin
      require 'openssl'

      OpenSSL::Digest::MD5.hexdigest('fips')

      FIPS = false
    rescue OpenSSL::Digest::DigestError, Exception
      # The first exception here is what should be used in the future.
      # However, not all versions of Ruby throw this error and so we need to
      # fall back to the most general case.

      FIPS = true
    end
  end
end
