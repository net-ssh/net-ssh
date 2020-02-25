module Net
  module SSH
    class KnownHosts
      # Searches an OpenSSH-style known-host file for a given host, and returns all
      # matching keys. This is used to implement host-key verification, as well as
      # to determine what key a user prefers to use for a given host. This is different
      # From the KnownHosts class in that it builds a cache of parsed known hosts in order
      # to avoid re-parsing known hosts earch time it is needed.
      class Cached
        def initialize(options)
          @user_files = Array(options[:user_known_hosts_file] || %w[~/.ssh/known_hosts ~/.ssh/known_hosts2])
          @global_files = Array(options[:global_known_hosts_file] || %w[/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2])
          @mtimes = {}
        end

        def search_for(host, options={})
          # Ensure cache is up to date
          build_cache if cache_invalid?
          hostname, host_ip = host.split(',')

          entries = []
          entries.concat @host_lookups.fetch(hostname, [])
          entries.concat @pattern_lookups.select { |pattern, _| hostname.match(pattern) }.values.flatten
          @hmac_lookups.each do |(hmac, salt), entry|
            digest = OpenSSL::Digest.new('sha1')
            host_hmac = OpenSSL::HMAC.digest(digest, salt, hostname)
            entries.concat(entry) if Base64.encode64(host_hmac).chomp == hmac
          end

          entries.select! { |entry| entry.hosts.include?(host_ip) } if options[:check_host_ip] && host_ip

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
            @mtimes[source] = File.mtime(source)
            file.each_line do |line|
              hosts, type, key_content = line.split(' ')
              # Skip empty line or one that is commented
              next if hosts.nil? || hosts.start_with?('#')

              hostlist = hosts.split(',')

              next unless KnownHosts::SUPPORTED_TYPE.include?(type)

              blob = key_content.unpack("m*").first
              key = Net::SSH::Buffer.new(blob).read_key

              hostlist.each do |host|
                entry = Entry.new(hostlist, key)
                if host.include?('*') || host.include?('?')
                  regex = regexify(host)
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

        def add(host, key, _options = nil)
          @host_lookups[host] ||= []
          @host_lookups[host] << Entry.new([host], key)

          @user_files.each do |file|
            begin
              # If this is the only modification since last read, update @mtimes to preserve cache
              preserve_cache = File.mtime(file) == @mtimes[file]
              KnownHosts.new(file).add(host, key)
              @mtimes[file] = File.mtime(file) if preserve_cache
              break
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

        def cache_invalid?
          (@user_files + @global_files).each do |file|
            return true if File.readable?(file) && @mtimes[file] != File.mtime(file)
          end
          false
        end
      end

      Entry = Struct.new(:hosts, :key)
    end
  end
end
