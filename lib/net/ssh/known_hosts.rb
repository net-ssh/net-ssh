require 'strscan'
require 'net/ssh/buffer'

module Net; module SSH
  class KnownHosts
    attr_reader :source

    class <<self
      def search_for(host)
        search_in(hostfiles, host)
      end

      def search_in(files, host)
        files.map { |file| KnownHosts.new(file).keys_for(host) }.flatten
      end

      def hostfiles
        @hostfiles ||= [
          "#{home_directory}/.ssh/known_hosts",
          "#{home_directory}/.ssh/known_hosts2",
          "/etc/ssh/ssh_known_hosts",
          "/etc/ssh_ssh_known_hosts2"
        ]
      end

      def home_directory
        ENV['HOME'] ||
          (ENV['HOMEPATH'] && "#{ENV['HOMEDRIVE']}#{ENV['HOMEPATH']}") ||
          "/"
      end

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

    def initialize(source)
      @source = source
    end

    def keys_for(host)
      keys = []
      return keys unless File.readable?(source)

      File.open(source) do |file|
        scanner = StringScanner.new("")
        file.each_line do |line|
          scanner.string = line

          scanner.skip(/\s*/)
          next if scanner.match?(/$|#/)

          hostlist = scanner.scan(/\S+/)
          next unless hostlist.split(/,/).include?(host)

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

    def add(host, key)
      File.open(source, "a") do |file|
        blob = [Net::SSH::Buffer.new.write_key(key).to_s].pack("m*")
        file.puts "#{host} #{key.ssh_type} #{blob}"
      end
    end

  end
end; end