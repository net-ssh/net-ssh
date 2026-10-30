require 'etc'
require 'set'

module Net
  module SSH
    # The Net::SSH::Config class is used to parse OpenSSH configuration files,
    # and translates that syntax into the configuration syntax that Net::SSH
    # understands. This lets Net::SSH scripts read their configuration (to
    # some extent) from OpenSSH configuration files (~/.ssh/config, /etc/ssh_config,
    # and so forth).
    #
    # Only a subset of OpenSSH configuration options are understood:
    #
    # * ChallengeResponseAuthentication => maps to the :auth_methods option challenge-response (then coleasced into keyboard-interactive)
    # * KbdInteractiveAuthentication => maps to the :auth_methods keyboard-interactive
    # * CertificateFile => maps to the :keycerts option
    # * Ciphers => maps to the :encryption option
    # * Compression => :compression
    # * CompressionLevel => :compression_level
    # * ConnectTimeout => maps to the :timeout option
    # * ControlPath => :control_path, used only when Net::SSH.start is given
    #   control_master: :auto; ControlMaster itself is not read
    # * ForwardAgent => :forward_agent
    # * GlobalKnownHostsFile => :global_known_hosts_file
    # * HostBasedAuthentication => maps to the :auth_methods option
    # * HostKeyAlgorithms => maps to :host_key option
    # * HostKeyAlias => :host_key_alias
    # * HostName => :host_name
    # * IdentityFile => maps to the :keys option
    # * IdentityAgent => :identity_agent
    # * IdentitiesOnly => :keys_only
    # * KexAlgorithms => maps to the :kex option
    # * CheckHostIP => :check_host_ip
    # * Macs => maps to the :hmac option
    # * PasswordAuthentication => maps to the :auth_methods option password
    # * Port => :port
    # * PreferredAuthentications => maps to the :auth_methods option
    # * ProxyCommand => maps to the :proxy option
    # * ProxyJump => maps to the :proxy option
    # * PubkeyAcceptedAlgorithms (or PubkeyAcceptedKeyTypes) => maps to :pubkey_algorithms
    # * PubKeyAuthentication => maps to the :auth_methods option
    # * RekeyLimit => :rekey_limit
    # * StrictHostKeyChecking => :verify_host_key
    # * User => :user
    # * UserKnownHostsFile => :user_known_hosts_file
    # * NumberOfPasswordPrompts => :number_of_password_prompts
    # * FingerprintHash => :fingerprint_hash
    #
    # Note that you will never need to use this class directly--you can control
    # whether the OpenSSH configuration files are read by passing the :config
    # option to Net::SSH.start. (They are, by default.)
    class Config
      class << self
        @@default_files = %w[~/.ssh/config /etc/ssh_config /etc/ssh/ssh_config]
        # The following defaults follow the openssh client ssh_config defaults.
        # http://lwn.net/Articles/544640/
        # "hostbased" is off and "none" is not supported but we allow it since
        # it's used by some clients to query the server for allowed auth methods
        @@default_auth_methods = %w[none publickey password keyboard-interactive]

        # Returns an array of locations of OpenSSH configuration files
        # to parse by default.
        def default_files
          @@default_files.clone
        end

        def default_auth_methods
          @@default_auth_methods.clone
        end

        # Loads the configuration data for the given +host+ from all of the
        # given +files+ (defaulting to the list of files returned by
        # #default_files), translates the resulting hash into the options
        # recognized by Net::SSH, and returns them.
        #
        # +user+ is the remote user given explicitly (e.g. to Net::SSH.start),
        # used by <tt>Match User</tt>; when nil, the User set so far by the
        # config, then the local user name, is used, as in OpenSSH.
        #
        # Match supports +all+, +Host+, +OriginalHost+, +User+ and +LocalUser+,
        # each optionally negated with a leading "!". A Match block with any
        # other condition (+exec+, +canonical+, +final+, +localnetwork+,
        # +tagged+, ...) never matches, and a warning naming the condition is
        # printed with Kernel#warn once per config line.
        def for(host, files = expandable_default_files, user: nil)
          translate(files.inject({}) { |settings, file|
            load(file, host, settings, user: user)
          })
        end

        # Load the OpenSSH configuration settings in the given +file+ for the
        # given +host+. If +settings+ is given, the options are merged into
        # that hash, with existing values taking precedence over newly parsed
        # ones. Returns a hash containing the OpenSSH options. (See
        # #translate for how to convert the OpenSSH options into Net::SSH
        # options.)
        def load(path, host, settings = {}, base_dir = nil, user: nil)
          file = File.expand_path(path)
          base_dir ||= File.dirname(file)
          return settings unless File.readable?(file)

          globals = {}
          block_matched = block_seen = false
          lineno = 0
          IO.foreach(file) do |line|
            lineno += 1
            next if line =~ /^\s*(?:#.*)?$/

            # As in OpenSSH, the keyword ends at the first whitespace or "=".
            key, value = line.strip.split(/\s*=\s*|\s+/, 2)

            # silently ignore malformed entries
            next if value.nil?

            key.downcase!
            value = uncomment(value)
            value = unquote(value)

            value = case value.strip
                    when /^\d+$/ then value.to_i
                    when /^no$/i then false
                    when /^yes$/i then true
                    else value
                    end

            if key == 'host'
              # Support "Host host1 host2 hostN".
              # See http://github.com/net-ssh/net-ssh/issues#issue/6
              negative_hosts, positive_hosts = value.to_s.split(/\s+/).partition { |h| h.start_with?('!') }

              # Check for negative patterns first. If the host matches, that overrules any other positive match.
              # The host substring code is used to strip out the starting "!" so the regexp will be correct.
              negative_matched = negative_hosts.any? { |h| host =~ pattern2regex(h[1..-1]) }

              if negative_matched
                block_matched = false
              else
                block_matched = positive_hosts.any? { |h| host =~ pattern2regex(h) }
              end

              block_seen = true
              settings[key] = host
            elsif key == 'match'
              block_matched = eval_match_conditions(value, host, [user, settings['user'], globals['user']].compact.first, "#{file} line #{lineno}")
              block_seen = true
            elsif !block_seen
              case key
              when 'identityfile', 'certificatefile'
                (globals[key] ||= []) << value
              when 'include'
                included_file_paths(base_dir, value).each do |file_path|
                  globals = load(file_path, host, globals, base_dir, user: user)
                end
              else
                globals[key] = value unless settings.key?(key)
              end
            elsif block_matched
              case key
              when 'identityfile', 'certificatefile'
                (settings[key] ||= []) << value
              when 'include'
                included_file_paths(base_dir, value).each do |file_path|
                  settings = load(file_path, host, settings, base_dir, user: user)
                end
              else
                settings[key] = value unless settings.key?(key)
              end
            end

            # ProxyCommand and ProxyJump override each other so they need to be tracked togeather
            [globals, settings].each do |hash|
              %w[proxyjump proxycommand].each do |proxy_key|
                if (proxy_value = hash.delete(proxy_key))
                  hash['proxy'] ||= [proxy_key, proxy_value]
                end
              end
            end
          end

          globals.merge(settings) do |key, oldval, newval|
            case key
            when 'identityfile', 'certificatefile'
              oldval + newval
            else
              newval
            end
          end
        end

        # Given a hash of OpenSSH configuration options, converts them into
        # a hash of Net::SSH options. Unrecognized options are ignored. The
        # +settings+ hash must have Strings for keys, all downcased, and
        # the returned hash will have Symbols for keys.
        def translate(settings)
          auth_methods = default_auth_methods.clone
          (auth_methods << 'challenge-response').uniq!
          ret = settings.each_with_object({ auth_methods: auth_methods }) do |(key, value), hash|
            translate_config_key(hash, key.to_sym, value, settings)
          end
          merge_challenge_response_with_keyboard_interactive(ret)
        end

        # Filters default_files down to the files that are expandable.
        def expandable_default_files
          default_files.keep_if do |path|
            File.expand_path(path)
            true
          rescue ArgumentError
            false
          end
        end

        private

        def translate_verify_host_key(value)
          case value
          when false
            :never
          when true
            :always
          when 'accept-new'
            :accept_new
          end
        end

        def translate_keepalive(hash, value)
          if value && value.to_i > 0
            hash[:keepalive] = true
            hash[:keepalive_interval] = value.to_i
          else
            hash[:keepalive] = false
          end
        end

        TRANSLATE_CONFIG_KEY_RENAME_MAP = {
          bindaddress: :bind_address,
          compression: :compression,
          compressionlevel: :compression_level,
          controlpath: :control_path,
          certificatefile: :keycerts,
          connecttimeout: :timeout,
          forwardagent: :forward_agent,
          identitiesonly: :keys_only,
          identityagent: :identity_agent,
          globalknownhostsfile: :global_known_hosts_file,
          hostkeyalias: :host_key_alias,
          identityfile: :keys,
          fingerprinthash: :fingerprint_hash,
          port: :port,
          user: :user,
          checkhostip: :check_host_ip
        }.freeze
        def translate_config_key(hash, key, value, settings) # rubocop:disable Metrics/AbcSize
          case key
          when :stricthostkeychecking
            hash[:verify_host_key] = translate_verify_host_key(value)
          when :ciphers
            hash[:encryption] = value.split(/,/)
          when :hostbasedauthentication
            if value
              (hash[:auth_methods] << "hostbased").uniq!
            else
              hash[:auth_methods].delete("hostbased")
            end
          when :hostkeyalgorithms
            hash[:host_key] = value.split(/,/)
          when :hostname
            hash[:host_name] = value.gsub(/%h/, settings['host'])
          when :kexalgorithms
            hash[:kex] = value.split(/,/)
          when :macs
            hash[:hmac] = value.split(/,/)
          when :serveralivecountmax
            hash[:keepalive_maxcount] = value.to_i if value
          when :serveraliveinterval
            translate_keepalive(hash, value)
          when :passwordauthentication
            if value
              (hash[:auth_methods] << 'password').uniq!
            else
              hash[:auth_methods].delete('password')
            end
          when :challengeresponseauthentication
            if value
              (hash[:auth_methods] << 'challenge-response').uniq!
            else
              hash[:auth_methods].delete('challenge-response')
            end
          when :kbdinteractiveauthentication
            if value
              (hash[:auth_methods] << 'keyboard-interactive').uniq!
            else
              hash[:auth_methods].delete('keyboard-interactive')
            end
          when :preferredauthentications
            hash[:auth_methods] = value.split(/,/) # TODO we should place to preferred_auth_methods rather than auth_methods
          when :proxy
            if (proxy = setup_proxy(*value))
              hash[:proxy] = proxy
            end
          when :pubkeyacceptedalgorithms, :pubkeyacceptedkeytypes
            hash[:pubkey_algorithms] = value.split(/,/)
          when :pubkeyauthentication
            if value
              (hash[:auth_methods] << 'publickey').uniq!
            else
              hash[:auth_methods].delete('publickey')
            end
          when :rekeylimit
            hash[:rekey_limit] = interpret_size(value)
          when :sendenv
            multi_send_env = value.to_s.split(/\s+/)
            hash[:send_env] = multi_send_env.map { |e| Regexp.new pattern2regex(e).source, false }
          when :setenv
            hash[:set_env] = Shellwords.split(value.to_s).map { |e| e.split '=', 2 }.to_h
          when :numberofpasswordprompts
            hash[:number_of_password_prompts] = value.to_i
          when :userknownhostsfile
            hash[:user_known_hosts_file] = value.split(/\s+/)
          when *TRANSLATE_CONFIG_KEY_RENAME_MAP.keys
            hash[TRANSLATE_CONFIG_KEY_RENAME_MAP[key]] = value
          end
        end

        def setup_proxy(type, value)
          case type
          when 'proxycommand'
            if value !~ /^none$/i
              require 'net/ssh/proxy/command'
              Net::SSH::Proxy::Command.new(value)
            end
          when 'proxyjump'
            if value !~ /^none$/i
              require 'net/ssh/proxy/jump'
              Net::SSH::Proxy::Jump.new(value)
            end
          end
        end

        # Converts an ssh_config pattern into a regex for matching against
        # host names.
        def pattern2regex(pattern, ignore_case: true)
          tail = pattern
          prefix = String.new
          while !tail.empty? do
            head, sep, tail = tail.partition(/[\*\?]/)
            prefix = prefix + Regexp.quote(head)
            case sep
            when '*'
              prefix += '.*'
            when '?'
              prefix += '.'
            when ''
            else
              fail "Unpexpcted sep:#{sep}"
            end
          end
          Regexp.new("^" + prefix + "$", ignore_case)
        end

        # Converts the given size into an integer number of bytes.
        def interpret_size(size)
          case size
          when /k$/i then size.to_i * 1024
          when /m$/i then size.to_i * 1024 * 1024
          when /g$/i then size.to_i * 1024 * 1024 * 1024
          else size.to_i
          end
        end

        def merge_challenge_response_with_keyboard_interactive(hash)
          if hash[:auth_methods].include?('challenge-response')
            hash[:auth_methods].delete('challenge-response')
            (hash[:auth_methods] << 'keyboard-interactive').uniq!
          end
          hash
        end

        def included_file_paths(base_dir, config_paths)
          tokenize_config_value(config_paths).flat_map do |path|
            Dir.glob(File.expand_path(path, base_dir)).select { |f| File.file?(f) }
          end
        end

        # Tokenize string into tokens.
        # A token is a word or a quoted sequence of words, separated by whitespaces.
        def tokenize_config_value(str)
          str.scan(/([^"\s]+)?(?:"([^"]+)")?\s*/).map(&:join)
        end

        MATCH_CONDITIONS_WITHOUT_ARGUMENT = %w[all canonical final].freeze
        SUPPORTED_MATCH_CONDITIONS = %w[all host originalhost user localuser].freeze

        def eval_match_conditions(condition, host, remote_user, location)
          # Not using `\s` for whitespace matching as canonical
          # ssh_config parser implementation (OpenSSH) has specific character set.
          # Ref: https://github.com/openssh/openssh-portable/blob/2581333d564d8697837729b3d07d45738eaf5a54/misc.c#L237-L239
          tokens = condition.split(/[ \t\r\n]+|(?<!=)=(?!=)/).reject(&:empty?)
          return true if tokens == ["all"]

          conditions = parse_match_conditions(tokens)
          unsupported = conditions.find { |_kind, name, exprs|
            !SUPPORTED_MATCH_CONDITIONS.include?(name) || (name != 'all' && exprs.nil?)
          }
          if unsupported
            warn_unsupported_match(unsupported[0], location)
            return false
          end

          !conditions.empty? && conditions.all? do |kind, name, exprs|
            kind.start_with?('!') ^ match_condition?(name, exprs, host, remote_user || local_user, conditions.size)
          end
        end

        def parse_match_conditions(tokens)
          conditions = []
          until tokens.empty?
            kind = tokens.shift
            name = kind.delete_prefix('!').downcase
            exprs = tokens.shift unless MATCH_CONDITIONS_WITHOUT_ARGUMENT.include?(name)
            conditions << [kind, name, exprs && unquote(exprs)]
          end
          conditions
        end

        def match_condition?(name, exprs, host, remote_user, condition_count)
          case name
          when "all"
            raise "all cannot be mixed with other conditions" if condition_count > 1

            true
          when "host"
            negated = exprs.start_with?('!')
            exprs = exprs[1..-1] if negated
            negated ^ exprs.split(",").any? { |expr| host =~ pattern2regex(expr) }
          when "originalhost"
            match_pattern_list(host, exprs)
          when "user"
            match_pattern_list(remote_user, exprs, ignore_case: false)
          when "localuser"
            match_pattern_list(local_user, exprs, ignore_case: false)
          end
        end

        # OpenSSH's match_pattern_list: true if any pattern matches and no "!pattern" does.
        def match_pattern_list(string, list, ignore_case: true)
          matched = false
          list.split(",").each do |pattern|
            negated = pattern.start_with?('!')
            next unless string =~ pattern2regex(negated ? pattern[1..-1] : pattern, ignore_case: ignore_case)
            return false if negated

            matched = true
          end
          matched
        end

        def warn_unsupported_match(kind, location)
          @warned_unsupported_matches ||= Set.new
          return unless @warned_unsupported_matches.add?([location, kind])

          Kernel.warn("net-ssh: #{location}: unsupported Match condition '#{kind}', the Match block is skipped")
        end

        def local_user
          Etc.getpwuid&.name || Etc.getlogin
        end

        # As in OpenSSH's argv_split, "#" starts a comment only at the start of a token and outside quotes.
        def uncomment(string)
          string[/\A(?:\s*(?!#)(?:\\.|"[^"]*"?|'[^']*'?|[^\s"'])+)*/]
        end

        def unquote(string)
          string =~ /^"(.*)"$/ ? Regexp.last_match(1) : string
        end
      end
    end
  end
end
