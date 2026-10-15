require 'digest/sha1'
require 'ipaddr'
require 'etc'
require 'socket'

module Net
  module SSH
    module Multiplex
      # Expands a ControlPath the way OpenSSH's ssh does: a leading ~ first,
      # then ${ENV} and the % tokens below in a single pass (ssh.c,
      # DEFAULT_CLIENT_PERCENT_EXPAND_ARGS in sshconnect.h, misc.c
      # percent_dollar_expand).
      #
      #   %%  a literal %
      #   %C  SHA1 hex of %l%h%p%r%j
      #   %d  local home directory
      #   %h  remote host name, after HostName
      #   %i  local uid
      #   %j  host of the last ProxyJump hop, or empty
      #   %k  the host key alias, or the host name as given
      #   %L  local host name up to the first dot
      #   %l  local host name
      #   %n  the host name as given
      #   %p  remote port
      #   %r  remote user
      #   %u  local user
      class ControlPath
        # +host_arg+ is the host as given, +host+ the one connected to after
        # HostName.
        def initialize(host_arg:, host:, port:, remote_user:, jump_host: '', host_key_alias: nil) # rubocop:disable Metrics/ParameterLists
          @host_arg = host_arg.to_s
          # ssh lowercases host names, but not addresses, before expanding.
          @host = address?(host.to_s) ? host.to_s : host.to_s.downcase
          @port = port.to_s
          @remote_user = remote_user.to_s
          @jump_host = jump_host.to_s
          @host_key_alias = host_key_alias
        end

        # Raises ArgumentError for an unknown % token or an unset ${ENV}
        # variable, which make ssh refuse the ControlPath too.
        def expand(path)
          expand_tokens(expand_tilde(path))
        end

        def tokens
          @tokens ||= begin
            pw = Etc.getpwuid(Process.uid)
            local_host = Socket.gethostname
            {
              'C' => Digest::SHA1.hexdigest("#{local_host}#{@host}#{@port}#{@remote_user}#{@jump_host}"),
              'd' => pw.dir,
              'h' => @host,
              'i' => Process.uid.to_s,
              'j' => @jump_host,
              'k' => @host_key_alias || @host_arg,
              'L' => local_host.split('.', 2).first,
              'l' => local_host,
              'n' => @host_arg,
              'p' => @port,
              'r' => @remote_user,
              'u' => pw.name
            }
          end
        end

        # The host ssh uses for %j: the last hop of a ProxyJump list, without
        # user or port (readconf.c, parse_jump).
        def self.jump_host(proxy_jump)
          last = proxy_jump.to_s.split(',').last.to_s.strip.delete_prefix('ssh://')
          last = last.split('@').last.to_s
          if last.start_with?('[')
            last[1...last.index(']').to_i]
          else
            last.split(':').first.to_s
          end
        end

        private

        # ssh uses the home directory from the password database, not $HOME
        # (misc.c, tilde_expand).
        def expand_tilde(path)
          return path unless path.start_with?('~')

          user, rest = path[1..].split('/', 2)
          home = user.nil? || user.empty? ? Etc.getpwuid(Process.uid).dir : Etc.getpwnam(user)&.dir
          raise ArgumentError, "unknown user in #{path}" if home.nil?

          rest.nil? ? home : File.join(home, rest)
        end

        def expand_tokens(path)
          path.gsub(/\$\{([^}]*)\}|%(.?)|\$\{.*/m) do
            if Regexp.last_match(1)
              name = Regexp.last_match(1)
              raise ArgumentError, "ControlPath has an empty ${} variable" if name.empty?

              ENV.fetch(name) { raise ArgumentError, "ControlPath variable ${#{name}} is not set" }
            elsif Regexp.last_match(2)
              token = Regexp.last_match(2)
              next '%' if token == '%'

              tokens.fetch(token) { raise ArgumentError, "ControlPath has unknown token %#{token}" }
            else
              raise ArgumentError, "ControlPath has an unterminated ${"
            end
          end
        end

        def address?(host)
          IPAddr.new(host)
          true
        rescue IPAddr::Error
          false
        end
      end
    end
  end
end
