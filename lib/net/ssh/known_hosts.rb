require 'strscan'
require 'net/ssh/buffer'

module Net; module SSH

  # Searches an OpenSSH-style known-host file for a given host, and returns all
  # matching keys. This is used to implement host-key verification, as well as
  # to determine what key a user prefers to use for a given host.
  #
  # This is used internally by Net::SSH, and will never need to be used directly
  # by consumers of the library.
  class KnownHosts
    class <<self
      # Searches all known host files (see KnownHosts.hostfiles) for all keys
      # of the given host. Returns an array of keys found.
      def search_for(host)
        search_in(hostfiles, host)
      end

      # Search for all known keys for the given host, in every file given in
      # the +files+ array. Returns the list of keys.
      def search_in(files, host)
        files.map { |file| KnownHosts.new(file).keys_for(host) }.flatten
      end

      # Returns an array of all known host files. Not all will actually exist.
      # You can add your own cust host files by prepending or appending to
      # this array:
      #
      #   KnownHosts.hostfiles.unshift "/path/to/my/host-file"
      #
      # Files are checked in the same order as returned by this array, so
      # by putting files on the front of this list, you indicate that they
      # should be tried first.
      def hostfiles
        @hostfiles ||= [
          "~/.ssh/known_hosts",
          "~/.ssh/known_hosts2",
          "/etc/ssh/ssh_known_hosts",
          "/etc/ssh_ssh_known_hosts2"
        ]
      end

      # Looks in all known host files (see KnownHosts.hostfiles) and tries to
      # add an entry for the given host and key to the first file it is able
      # to.
      def add(host, key)
        hostfiles.each do |file|
          begin
            KnownHosts.new(file).add(host, key)
            return
          rescue SystemCallError
            # try the next hostfile
          end
        end
      end
    end

    # The host-key file name that this KnownHosts instance will use to search
    # for keys.
    attr_reader :source

    # Instantiate a new KnownHosts instance that will search the given known-hosts
    # file. The path is expanded file File.expand_path.
    def initialize(source)
      @source = File.expand_path(source)
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
    def keys_for(host)
      keys = []
      return keys unless File.readable?(source)

      entries = host.split(/,/)

      File.open(source) do |file|
        scanner = StringScanner.new("")
        file.each_line do |line|
          scanner.string = line

          scanner.skip(/\s*/)
          next if scanner.match?(/$|#/)

          hostlist = scanner.scan(/\S+/).split(/,/)
          next unless entries.all? { |entry| hostlist.include?(entry) }

          scanner.skip(/\s*/)
          type = scanner.scan(/\S+/)

          next unless %w(ssh-rsa ssh-dss).include?(type)

          scanner.skip(/\s*/)
          blob = scanner.rest.unpack("m*").first
          keys << Net::SSH::Buffer.new(blob).read_key
        end
      end

      keys
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

  end
end; end