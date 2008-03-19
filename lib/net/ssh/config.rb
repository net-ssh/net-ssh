module Net; module SSH
  class Config
    class <<self
      @@default_files = %w(~/.ssh/config /etc/ssh_config /etc/ssh/ssh_config)
      def default_files
        @@default_files
      end

      def for(host, files=default_files)
        settings = load_all(files, host)

        settings.inject({}) do |hash, (key, value)|
          case key
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
          when 'globalknownhostsfile'
            # FIXME
          when 'hostbasedauthentication' then
            if value
              hash[:auth_methods] ||= []
              hash[:auth_methods] << "hostbased"
            end
          when 'hostkeyalgorithms' then
            hash[:host_key] = value.split(/,/)
          when 'hostkeyalias' then
            # FIXME
          when 'hostname' then
            # FIXME
          when 'identityfile' then
            hash[:keys] = value
          when 'localforward' then
            # FIXME
          when 'macs' then
            hash[:hmac] = value.split(/,/)
          when 'passwordauthentication'
            if value
              hash[:auth_methods] ||= []
              hash[:auth_methods] << "password"
            end
          when 'port'
            hash[:port] = value
          when 'preferredauthentications'
            hash[:auth_methods] = value.split(/,/)
          when 'pubkeyauthentication'
            if value
              hash[:auth_methods] ||= []
              hash[:auth_methods] << "publickey"
            end
          when 'rekeylimit'
            hash[:rekey_limit] = interpret_size(value)
          when 'sendenv'
            # FIXME
          when 'user'
            # FIXME
          when 'userknownhostsfile'
            # FIXME
          end
          hash
        end
      end

      def load(file, host, settings={})
        file = File.expand_path(file)
        return settings unless File.readable?(file)

        in_match = false
        IO.foreach(file) do |line|
          next if line =~ /^\s*(?:#.*)?$/

          key, value = line.strip.split(/\s+/, 2)
          key.downcase!

          value = $1 if value =~ /^"(.*)"$/
          value = case value.strip
            when /^\d+$/ then value.to_i
            when /^no$/i then false
            when /^yes$/i then true
            else value
            end

          if key == 'host'
            in_match = (host =~ pattern2regex(value))
          elsif in_match
            if key == 'identityfile'
              settings[key] ||= []
              settings[key] << value
            else
              settings[key] ||= value
            end
          end
        end

        return settings
      end

      def load_all(files, host)
        files.inject({}) { |settings, file| load(file, host, settings) }
      end

      private

        def pattern2regex(pattern)
          pattern = "^" + pattern.gsub(/\./, "\\.").
            gsub(/\?/, '.').
            gsub(/\*/, '.*') + "$"
          Regexp.new(pattern, true)
        end

        def interpret_size(size)
          case size
          when /k$/i then size.to_i * 1024
          when /m$/i then size.to_i * 1024 * 1024
          when /g$/i then size.to_i * 1024 * 1024 * 1024
          else size.to_i
          end
        end
    end
  end
end; end
