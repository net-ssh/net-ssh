module Net; module SSH

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
  # * Ciphers => maps to the :encryption option
  # * Compression => :compression
  # * CompressionLevel => :compression_level
  # * ConnectTimeout => maps to the :timeout option
  # * ForwardAgent => :forward_agent
  # * GlobalKnownHostsFile => :global_known_hosts_file
  # * HostBasedAuthentication => maps to the :auth_methods option
  # * HostKeyAlgorithms => maps to :host_key option
  # * HostKeyAlias => :host_key_alias
  # * HostName => :host_name
  # * IdentityFile => maps to the :keys option
  # * IdentitiesOnly => :keys_only
  # * Macs => maps to the :hmac option
  # * PasswordAuthentication => maps to the :auth_methods option password
  # * Port => :port
  # * PreferredAuthentications => maps to the :auth_methods option
  # * ProxyCommand => maps to the :proxy option
  # * PubKeyAuthentication => maps to the :auth_methods option
  # * RekeyLimit => :rekey_limit
  # * User => :user
  # * UserKnownHostsFile => :user_known_hosts_file
  # * NumberOfPasswordPrompts => :number_of_password_prompts
  #
  # Note that you will never need to use this class directly--you can control
  # whether the OpenSSH configuration files are read by passing the :config
  # option to Net::SSH.start. (They are, by default.)
  class Config
    class << self
      @@default_files = %w(~/.ssh/config /etc/ssh_config /etc/ssh/ssh_config)
      # The following defaults follow the openssh client ssh_config defaults.
      # http://lwn.net/Articles/544640/
      # "hostbased" is off and "none" is not supported but we allow it since
      # it's used by some clients to query the server for allowed auth methods
      @@default_auth_methods = %w(none publickey password keyboard-interactive)

      # Returns an array of locations of OpenSSH configuration files
      # to parse by default.
      def default_files
        @@default_files
      end

      def default_auth_methods
        @@default_auth_methods
      end

      # Loads the configuration data for the given +host+ from all of the
      # given +files+ (defaulting to the list of files returned by
      # #default_files), translates the resulting hash into the options
      # recognized by Net::SSH, and returns them.
      def for(host, files=default_files)
        translate(files.inject({}) { |settings, file|
          load(file, host, settings)
        })
      end

      # Load the OpenSSH configuration settings in the given +file+ for the
      # given +host+. If +settings+ is given, the options are merged into
      # that hash, with existing values taking precedence over newly parsed
      # ones. Returns a hash containing the OpenSSH options. (See
      # #translate for how to convert the OpenSSH options into Net::SSH
      # options.)
      def load(path, host, settings={})
        file = File.expand_path(path)
        return settings unless File.readable?(file)

        globals = {}
        matched_host = nil
        seen_host = false
        IO.foreach(file) do |line|
          next if line =~ /^\s*(?:#.*)?$/

          if line =~ /^\s*(\S+)\s*=(.*)$/
            key, value = $1, $2
          else
            key, value = line.strip.split(/\s+/, 2)
          end

          # silently ignore malformed entries
          next if value.nil?

          key.downcase!
          value = $1 if value =~ /^"(.*)"$/

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
            negative_match = negative_hosts.select { |h| host =~ pattern2regex(h[1..-1]) }.first

            if negative_match
              matched_host = nil
            else
              matched_host = positive_hosts.select { |h| host =~ pattern2regex(h) }.first
            end

            seen_host = true
            settings[key] = host
          elsif !seen_host
            if key == 'identityfile'
              (globals[key] ||= []) << value
            else
              globals[key] = value unless settings.key?(key)
            end
          elsif !matched_host.nil?
            if key == 'identityfile'
              (settings[key] ||= []) << value
            else
              settings[key] = value unless settings.key?(key)
            end
          end
        end

        settings = globals.merge(settings) if globals

        return settings
      end

      # Given a hash of OpenSSH configuration options, converts them into
      # a hash of Net::SSH options. Unrecognized options are ignored. The
      # +settings+ hash must have Strings for keys, all downcased, and
      # the returned hash will have Symbols for keys.
      def translate(settings)
        auth_methods = default_auth_methods.clone
        (auth_methods << 'challenge-response').uniq!
        ret = settings.inject({:auth_methods=>auth_methods}) do |hash, (key, value)|
          case key
          when 'bindaddress' then
            hash[:bind_address] = value
          when 'ciphers' then
            hash[:encryption] = value.split(/,/)
          when 'compression' then
            hash[:compression] = value
          when 'compressionlevel' then
            hash[:compression_level] = value
          when 'connecttimeout' then
            hash[:timeout] = value
          when 'forwardagent' then
            hash[:forward_agent] = value
          when 'identitiesonly' then
            hash[:keys_only] = value
          when 'globalknownhostsfile'
            hash[:global_known_hosts_file] = value
          when 'hostbasedauthentication' then
            if value
              (hash[:auth_methods] << "hostbased").uniq!
            else
              hash[:auth_methods].delete("hostbased")
            end
          when 'hostkeyalgorithms' then
            hash[:host_key] = value.split(/,/)
          when 'hostkeyalias' then
            hash[:host_key_alias] = value
          when 'hostname' then
            hash[:host_name] = value.gsub(/%h/, settings['host'])
          when 'identityfile' then
            hash[:keys] = value
          when 'macs' then
            hash[:hmac] = value.split(/,/)
          when 'serveralivecountmax'
            hash[:keepalive_maxcount] = value.to_i if value
          when 'serveraliveinterval'
            if value && value.to_i > 0
              hash[:keepalive] = true
              hash[:keepalive_interval] = value.to_i
            else
              hash[:keepalive] = false
            end
          when 'passwordauthentication'
            if value
              (hash[:auth_methods] << 'password').uniq!
            else
              hash[:auth_methods].delete('password')
            end
          when 'challengeresponseauthentication'
            if value
              (hash[:auth_methods] << 'challenge-response').uniq!
            else
              hash[:auth_methods].delete('challenge-response')
            end
          when 'kbdinteractiveauthentication'
            if value
              (hash[:auth_methods] << 'keyboard-interactive').uniq!
            else
              hash[:auth_methods].delete('keyboard-interactive')
            end
          when 'port'
            hash[:port] = value
          when 'preferredauthentications'
            hash[:auth_methods] = value.split(/,/) # TODO we should place to preferred_auth_methods rather than auth_methods
          when 'proxycommand'
            if value and !(value =~ /^none$/)
              require 'net/ssh/proxy/command'
              hash[:proxy] = Net::SSH::Proxy::Command.new(value)
            end
	        when 'pubkeyauthentication'
            if value
              (hash[:auth_methods] << 'publickey').uniq!
            else
              hash[:auth_methods].delete('publickey')
            end
          when 'rekeylimit'
            hash[:rekey_limit] = interpret_size(value)
          when 'user'
            hash[:user] = value
          when 'userknownhostsfile'
            hash[:user_known_hosts_file] = value
          when 'sendenv'
            multi_send_env = value.to_s.split(/\s+/)
            hash[:send_env] = multi_send_env.map { |e| Regexp.new pattern2regex(e).source, false }
          when 'numberofpasswordprompts'
            hash[:number_of_password_prompts] = value.to_i
          end
          hash
        end
        merge_challenge_response_with_keyboard_interactive(ret)
      end

      private

        # Converts an ssh_config pattern into a regex for matching against
        # host names.
        def pattern2regex(pattern)
          tail = pattern
          prefix = ""
          while !tail.empty? do
            head,sep,tail = tail.partition(/[\*\?]/)
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
          Regexp.new("^" + prefix + "$", true)
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
    end
  end

end; end
