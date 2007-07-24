require 'strscan'
require 'net/ssh/buffer'

module Net; module SSH
  class KnownHosts
    attr_reader :source

    def self.search_in(files, host)
      files.map { |file| KnownHosts.new(file).keys_for(host) }.flatten
    end

    def initialize(source)
      @source = source
    end

    def keys_for(host)
      keys = []

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