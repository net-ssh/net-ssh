require 'net/ssh/errors'
require 'net/ssh/known_hosts'

module Net
  module SSH
    module Verifiers
      # Does a strict host verification, looking the server up in the known
      # host files to see if a key has already been seen for this server. If this
      # server does not appear in any host file, an exception will be raised
      # (HostKeyUnknown). This is in contrast to the "Strict" class, which will
      # silently add the key to your known_hosts file. If the server does appear at
      # least once, but the key given does not match any known for the server, an
      # exception will be raised (HostKeyMismatch).
      # Otherwise, this returns true.
      class Always
        def verify(arguments)
          host_keys = arguments[:session].host_keys

          # We've never seen this host before, so raise an exception.
          process_cache_miss(host_keys, arguments, HostKeyUnknown, "is unknown") if host_keys.empty?

          # Find the known-hosts entry whose key matches the presented certificate.
          found_key = host_keys.find do |key|
            if key.respond_to?(:matches_key?)
              key.matches_key?(arguments[:key])
            else
              key.ssh_type == arguments[:key].ssh_type && key.to_blob == arguments[:key].to_blob
            end
          end

          # No matching entry found — key is not recognized.
          process_cache_miss(host_keys, arguments, HostKeyMismatch, "does not match") unless found_key

          # For @cert-authority entries, enforce the certificate constraints
          # OpenSSH checks in sshkey_cert_check_authority. A certificate signed by
          # the trusted CA but failing any of these is rejected with
          # HostKeyMismatch (not HostKeyUnknown) so AcceptNew does not swallow the
          # failure and remember the rejected certificate.
          verify_certificate!(found_key, host_keys, arguments)

          true
        end

        def verify_signature(&block)
          yield
        end

        private

        # Enforces the @cert-authority certificate constraints for entries that
        # implement them (Net::SSH::HostKeyEntries::CertAuthority). Non-certificate
        # entries do not respond to these predicates and are left untouched.
        def verify_certificate!(entry, host_keys, arguments)
          cert = arguments[:key]

          if entry.respond_to?(:matches_validity?) && !entry.matches_validity?(cert)
            reason = if cert.valid_before && cert.valid_before < Time.now
                       "Certificate has expired"
                     else
                       "Certificate is not yet valid"
                     end
            process_cache_miss(host_keys, arguments, HostKeyMismatch, reason)
          end

          if entry.respond_to?(:matches_principal?) && !entry.matches_principal?(cert, host_keys.hostname)
            process_cache_miss(host_keys, arguments, HostKeyMismatch,
                               "Certificate invalid: name is not a listed principal")
          end

          if entry.respond_to?(:matches_type?) && !entry.matches_type?(cert)
            process_cache_miss(host_keys, arguments, HostKeyMismatch,
                               "Certificate invalid: not a host certificate")
          end

          return unless entry.respond_to?(:critical_options_supported?) && !entry.critical_options_supported?(cert)

          process_cache_miss(host_keys, arguments, HostKeyMismatch,
                             "Certificate invalid: unsupported critical option")
        end

        def process_cache_miss(host_keys, args, exc_class, message)
          exception = exc_class.new("fingerprint #{args[:fingerprint]} " +
                                    "#{message} for #{host_keys.host.inspect}")
          exception.data = args
          exception.callback = Proc.new do
            host_keys.add_host_key(args[:key])
          end
          raise exception
        end
      end
    end
  end
end
