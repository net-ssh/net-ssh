module Net
  module SSH
    class KnownHosts
      class Cached
        def initialize(options)
          @user_files = Array(options[:user_known_hosts_file] || %w[~/.ssh/known_hosts ~/.ssh/known_hosts2])
          @global_files = Array(options[:global_known_hosts_file] || %w[/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2])
          build_cache
        end

        def search_for(host, options={})
          hostname, host_ip = host.split(',')

          entries = []
          entries.concat @host_lookups.fetch(hostname, [])
          entries.concat @pattern_lookups.select { |pattern, _| hostname.match(pattern) }.values.flatten
          @hmac_lookups.each do |(hmac, salt), entry|
            digest = OpenSSL::Digest.new('sha1')
            host_hmac = OpenSSL::HMAC.digest(digest, salt, hostname)
            entries << entry if Base64.encode64(host_hmac.chomp) == hmac
          end

          if options[:check_host_ip] && host_ip
            entries.select! { |entry| entry.hosts.include?(host_ip) }
          end

          HostKeys.new(entries.map(&:key), host, self, options)
        end

        def build_cache
          @host_lookups = {}
          @hmac_lookups = {}
          @pattern_lookups = {}
          (@user_files + @global_files).each do |file|
            parse_known_hosts(File.expand_path(file))
          end
        end

        def parse_known_hosts(source)
          return unless File.readable?(source)

          File.open(source) do |file|
            file.each_line do |line|
              hosts, type, key_content = line.split(' ')
              next unless hosts || hosts.start_with?('#')

              hostlist = hosts.split(',')

              next unless KnownHosts::SUPPORTED_TYPE.include?(type)

              blob = key_content.unpack("m*").first
              key = Net::SSH::Buffer.new(blob).read_key

              hostlist.each do |host|
                entry = Entry.new(hostlist, key)
                if host.include?('*') || host.include?('?')
                  regex = regexify_pattern(host)
                  @pattern_lookups[regex] ||= []
                  @pattern_lookups[regex] << entry
                elsif host =~ /\A\|1(\|.+){2}\z/
                  chunks = host.split('|')
                  salt = Base64.decode64(chunks[2])
                  hmac = chunks[3]
                  cache_key = [hmac, salt]
                  @hmac_lookups[cache_key] ||= []
                  @hmac_lookups[cache_key] << entry
                else
                  @host_lookups[host] ||= []
                  @host_lookups[host] << entry
                end
              end
            end
          end
        end

        def add(host, key)
          @host_lookups[host] ||= []
          @host_lookups[host] << Entry.new([host], key)

          @user_files.each do |file|
            begin
              KnownHosts.new(file).add(host, key)
              return
            rescue SystemCallError
            end
          end
        end

        def regexify(pattern)
          # see man 8 sshd for pattern details
          pattern_regexp = pattern.split('*').map do |x|
            x.split('?').map do |y|
              Regexp.escape(y)
            end.join('.')
          end.join('[^.]*')

          Regexp.new("\\A#{pattern_regexp}\\z")
        end
      end

      Entry = Struct.new(:hosts, :key)
    end
  end
end


