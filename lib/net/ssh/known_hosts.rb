require 'strscan'
require 'openssl'
require 'open3'
require 'shellwords'
require 'net/ssh/buffer'
require 'net/ssh/authentication/ed25519_loader'
require 'net/ssh/multiplex/control_path'

module Net
  module SSH
    module HostKeyEntries
      # regular public key entry
      class PubKey
        # The public key itself, e.g. an OpenSSL::PKey::PKey.
        attr_reader :key

        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        def ssh_type
          @key.ssh_type
        end

        def ssh_types
          [ssh_type]
        end

        def to_blob
          @key.to_blob
        end

        def matches_key?(server_key)
          @key.ssh_type == server_key.ssh_type && @key.to_blob == server_key.to_blob
        end

        def method_missing(name, *args, &block)
          return super unless @key.respond_to?(name)

          raise NoMethodError.new(
            "undefined method `#{name}' for #{self.class}; call it on #key, the wrapped public key",
            name
          )
        end

        def respond_to_missing?(_name, _include_private = false)
          false
        end
      end

      # @cert-authority entry
      class CertAuthority
        def ssh_types
          %w[
            ecdsa-sha2-nistp256-cert-v01@openssh.com
            ecdsa-sha2-nistp384-cert-v01@openssh.com
            ecdsa-sha2-nistp521-cert-v01@openssh.com
            ssh-ed25519-cert-v01@openssh.com
            ssh-rsa-cert-v01@openssh.com
            ssh-rsa-cert-v00@openssh.com
          ]
        end

        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        def matches_key?(server_key)
          if ssh_types.include?(server_key.ssh_type)
            server_key.signature_valid? && (server_key.signature_key.to_blob == @key.to_blob)
          else
            false
          end
        end

        # Returns true if the certificate lists no principals (unrestricted) or
        # if the given hostname matches a listed principal. Host-certificate
        # principals are shell-glob patterns, matching OpenSSH, whose
        # sshkey_cert_check_host passes wildcard_pattern=1 so principals like
        # "*.example.com" are matched with match_pattern rather than strcmp.
        def matches_principal?(server_key, hostname)
          server_key.valid_principals.empty? ||
            server_key.valid_principals.any? { |principal| File.fnmatch(principal, hostname) }
        end

        # Returns true if the certificate's validity window covers the current time.
        def matches_validity?(server_key)
          return false if server_key.valid_after && server_key.valid_after > Time.now
          return false if server_key.valid_before && server_key.valid_before < Time.now

          true
        end

        # Returns true if the certificate is a host certificate. A user
        # certificate (type :user) must never authenticate a host.
        def matches_type?(server_key)
          server_key.type == :host
        end

        # Returns true if every critical option in the certificate is one we can
        # enforce. net-ssh enforces none, so any critical option is unsupported
        # and, as OpenSSH does, must cause the certificate to be rejected.
        def critical_options_supported?(server_key)
          server_key.critical_options.empty?
        end
      end

      # @revoked entry
      class Revoked
        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        # Returns true for the revoked key itself and for any certificate that
        # wraps it or is signed by it, matching OpenSSH's check_key_not_revoked.
        def matches_key?(server_key)
          keys = [server_key]
          keys += [server_key.key, server_key.signature_key] if server_key.respond_to?(:signature_key)
          keys.any? { |key| key.ssh_type == @key.ssh_type && key.to_blob == @key.to_blob }
        end
      end
    end

    # Represents the result of a search in known hosts
    # see search_for
    class HostKeys
      include Enumerable
      attr_reader :host

      def initialize(host_keys, host, known_hosts, options = {}, revoked_keys = [])
        @host_keys = host_keys
        @host = host
        @known_hosts = known_hosts
        @options = options
        @revoked_keys = revoked_keys
      end

      # Returns true if a @revoked known-hosts entry for this host matches +key+.
      def revoked?(key)
        @revoked_keys.any? { |entry| entry.matches_key?(key) }
      end

      def add_host_key(key)
        @known_hosts.add(@host, key, @options)
        @host_keys.push(key)
      end

      def each(&block)
        @host_keys.each(&block)
      end

      def empty?
        @host_keys.empty?
      end

      # Returns the bare hostname, stripping port and IP portions from the
      # comma-separated host string used internally.
      #
      # Examples:
      #   "server.example.com"            => "server.example.com"
      #   "server.example.com,1.2.3.4"    => "server.example.com"
      #   "[server.example.com]:2222"      => "server.example.com"
      def hostname
        @host.split(",").first.gsub(/\[|\]:\d+/, "")
      end
    end

    # Searches an OpenSSH-style known-host file for a given host, and returns all
    # matching keys. This is used to implement host-key verification, as well as
    # to determine what key a user prefers to use for a given host.
    #
    # This is used internally by Net::SSH, and will never need to be used directly
    # by consumers of the library.
    class KnownHosts
      SUPPORTED_TYPE = %w[ssh-rsa ssh-dss
                          ecdsa-sha2-nistp256
                          ecdsa-sha2-nistp384
                          ecdsa-sha2-nistp521]

      SUPPORTED_TYPE.push('ssh-ed25519') if Net::SSH::Authentication::ED25519Loader::LOADED

      class << self
        # Searches all known host files (see KnownHosts.hostfiles) and the
        # output of :known_hosts_command for all keys of the given host.
        # Returns an enumerable of keys found.
        def search_for(host, options = {})
          sources = hostfiles(options).map { |file| KnownHosts.new(file) }
          sources += known_hosts_command(host, options)
          revoked_keys = sources.flat_map { |source| source.revoked_keys_for(host) }
          HostKeys.new(sources.flat_map { |source| source.keys_for(host, options) }, host, self, options, revoked_keys)
        end

        # Search for all known keys for the given host, in every file given in
        # the +files+ array. Returns the list of keys. @revoked entries are not
        # included.
        def search_in(files, host, options = {})
          files.flat_map { |file| KnownHosts.new(file).keys_for(host, options) }
        end

        # Looks in the given +options+ hash for the :user_known_hosts_file and
        # :global_known_hosts_file keys, and returns an array of all known
        # hosts files. If the :user_known_hosts_file key is not set, the
        # default is returned (~/.ssh/known_hosts and ~/.ssh/known_hosts2). If
        # :global_known_hosts_file is not set, the default is used
        # (/etc/ssh/ssh_known_hosts and /etc/ssh/ssh_known_hosts2).
        #
        # If you only want the user known host files, you can pass :user as
        # the second option.
        def hostfiles(options, which = :all)
          files = []

          files += Array(options[:user_known_hosts_file] || %w[~/.ssh/known_hosts ~/.ssh/known_hosts2]) if which == :all || which == :user

          if which == :all || which == :global
            files += Array(options[:global_known_hosts_file] || %w[/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2])
          end

          return files
        end

        # Looks in all user known host files (see KnownHosts.hostfiles) and tries to
        # add an entry for the given host and key to the first file it is able
        # to.
        def add(host, key, options = {})
          hostfiles(options, :user).each do |file|
            KnownHosts.new(file).add(host, key)
            return
          rescue SystemCallError
            # try the next hostfile
          end
        end

        private

        # Runs :known_hosts_command as ssh_config's KnownHostsCommand does and
        # returns its output as a KnownHosts, in an array that is empty when
        # the option is unset or "none", or the command fails. The host key is
        # looked up before the server sends it, so %f, %K and %t are "NONE",
        # as in OpenSSH's ORDER invocation.
        def known_hosts_command(host, options)
          command = options[:known_hosts_command]
          return [] if command.nil? || command.to_s == 'none'

          program, *args = Shellwords.split(command.to_s)
          return [] if program.nil?

          expander = known_hosts_command_expander(host, options)
          # Like OpenSSH, expand tokens in the arguments only, and run without a
          # shell so that no expanded value is interpreted.
          output, status = Open3.capture2([program, program], *args.map { |arg| expander.expand_tokens(arg) })
          unless status.success?
            options[:logger]&.warn { "KnownHostsCommand #{command.inspect} failed: #{status}" }
            return []
          end

          [KnownHosts.new("KnownHostsCommand", content: output)]
        rescue ArgumentError, SystemCallError => e
          options[:logger]&.warn { "KnownHostsCommand #{command.inspect} failed: #{e.message}" }
          []
        end

        # The host as given to Net::SSH.start isn't known here, so %n is
        # unsupported and %k falls back to the host after HostName.
        def known_hosts_command_expander(host, options)
          host_name = options[:host_name] || host.split(',').first.gsub(/\[|\]:\d+/, '')
          jump_host = if defined?(Net::SSH::Proxy::Jump) && options[:proxy].is_a?(Net::SSH::Proxy::Jump)
                        Multiplex::ControlPath.jump_host(options[:proxy].jump_proxies)
                      else
                        ''
                      end

          Multiplex::ControlPath.new(
            host_arg: host_name, host: host_name, port: options[:port] || 22,
            remote_user: options[:remote_user] || options[:user], jump_host: jump_host,
            host_key_alias: options[:host_key_alias],
            extra_tokens: { 'H' => host.split(',').first, 'I' => 'HOSTNAME', 'f' => 'NONE', 'K' => 'NONE', 't' => 'NONE', 'n' => nil }
          )
        end
      end

      # The host-key file name that this KnownHosts instance will use to search
      # for keys.
      attr_reader :source

      # Instantiate a new KnownHosts instance that will search the given known-hosts
      # file. The path is expanded file File.expand_path. If +content+ is given,
      # it is searched instead, and +source+ only names it.
      def initialize(source, content: nil)
        @content = content
        @source = content ? source : File.expand_path(source)
      rescue ArgumentError
        @source = source
      end

      # Returns an array of all keys that are known to be associatd with the
      # given host. The +host+ parameter is either the domain name or ip address
      # of the host, or both (comma-separated). Additionally, if a non-standard
      # port is being used, it may be specified by putting the host (or ip, or
      # both) in square brackets, and appending the port outside the brackets
      # after a colon. Possible formats for +host+, then, are;
      #
      #   "net.ssh.test"
      #   "1.2.3.4"
      #   "net.ssh.test,1.2.3.4"
      #   "[net.ssh.test]:5555"
      #   "[1,2,3,4]:5555"
      #   "[net.ssh.test]:5555,[1.2.3.4]:5555
      #
      # @revoked entries are not included, see revoked_keys_for.
      def keys_for(host, options = {})
        keys = []
        entries = host.split(/,/)
        host_name = entries[0]
        host_ip = entries[1]

        each_entry do |marker, hostlist, key_content, comment|
          next if marker == "@revoked"

          found = hostlist.any? { |pattern| match(host_name, pattern) } || known_host_hash?(hostlist, entries)
          next unless found

          found = hostlist.include?(host_ip) if options[:check_host_ip] && entries.size > 1 && hostlist.size > 1
          next unless found

          raw_key = read_key(key_content)

          keys <<
            if marker == "@cert-authority"
              HostKeyEntries::CertAuthority.new(raw_key, comment: comment)
            else
              HostKeyEntries::PubKey.new(raw_key, comment: comment)
            end
        end

        keys
      end

      # Returns the @revoked entries for the given host, which takes the same
      # formats as keys_for. An entry matching any of the comma-separated names
      # counts, so :check_host_ip can't narrow a revocation.
      def revoked_keys_for(host)
        keys = []
        entries = host.split(/,/)

        each_entry do |marker, hostlist, key_content, comment|
          next unless marker == "@revoked"

          found = entries.any? { |entry| hostlist.any? { |pattern| match(entry, pattern) } }
          next unless found || known_host_hash?(hostlist, entries)

          keys << HostKeyEntries::Revoked.new(read_key(key_content), comment: comment)
        end

        keys
      end

      def match(host, pattern)
        if pattern.include?('*') || pattern.include?('?')
          # see man 8 sshd for pattern details
          pattern_regexp = pattern.split('*', -1).map do |x|
            x.split('?', -1).map do |y|
              Regexp.escape(y)
            end.join('.')
          end.join('.*')

          host =~ Regexp.new("\\A#{pattern_regexp}\\z")
        else
          host == pattern
        end
      end

      # Indicates whether one of the entries matches an hostname that has been
      # stored as a HMAC-SHA1 hash in the known hosts.
      def known_host_hash?(hostlist, entries)
        if hostlist.size == 1 && hostlist.first =~ /\A\|1(\|.+){2}\z/
          chunks = hostlist.first.split(/\|/)
          salt = chunks[2].unpack1("m")
          digest = OpenSSL::Digest.new('sha1')
          entries.each do |entry|
            hmac = OpenSSL::HMAC.digest(digest, salt, entry)
            return true if [hmac].pack("m").chomp == chunks[3]
          end
        end
        false
      end

      # Tries to append an entry to the current source file for the given host
      # and key. If it is unable to (because the file is not writable, for
      # instance), an exception will be raised.
      def add(host, key)
        File.open(source, "a") do |file|
          blob = [Net::SSH::Buffer.from(:key, key).to_s].pack("m*").gsub(/\s/, "")
          file.puts "#{host} #{key.ssh_type} #{blob}"
        end
      end

      private

      # Yields the marker, host patterns, key and comment of each usable line.
      def each_entry
        each_line do |line|
          fields = line.split(' ')
          marker = fields.shift if fields.first&.start_with?('@')
          hosts, type, key_content, comment = fields

          # Skip empty line or one that is commented
          next if hosts.nil? || hosts.start_with?('#')

          next unless SUPPORTED_TYPE.include?(type)

          yield marker, hosts.split(','), key_content, comment
        end
      end

      def each_line(&block)
        return @content.each_line(&block) if @content
        return unless File.readable?(source)

        File.foreach(source, &block)
      end

      def read_key(key_content)
        Net::SSH::Buffer.new(key_content.unpack("m*").first).read_key
      end
    end
  end
end
