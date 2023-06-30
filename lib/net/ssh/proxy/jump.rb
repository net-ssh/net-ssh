require 'tempfile'
require 'uri'
require 'net/ssh/proxy/command'

module Net
  module SSH
    module Proxy
      # An implementation of a jump proxy. To use it, instantiate it,
      # then pass the instantiated object via the :proxy key to
      # Net::SSH.start:
      #
      #   require 'net/ssh/proxy/jump'
      #
      #   proxy = Net::SSH::Proxy::Jump.new('user@proxy', options: ["StrictHostKeyChecking=no"])
      #   Net::SSH.start('host', 'user', :proxy => proxy) do |ssh|
      #     ...
      #   end
      class Jump < Command
        # The jump proxies
        attr_reader :jump_proxies

        # Create a new socket factory that tunnels via multiple jump proxes as
        # [user@]host[:port].
        def initialize(jump_proxies, options: [])
          @jump_proxies = jump_proxies
          @options = options
          @key_data_tempfiles = []
        end

        # Return a new socket connected to the given host and port via the jump
        # proxy that was requested when the socket factory was instantiated.
        def open(host, port, connection_options = nil)
          build_proxy_command_equivalent(connection_options)
          super
        end

        # We cannot build the ProxyCommand template until we know if the :config
        # option was specified during `Net::SSH.start`.
        def build_proxy_command_equivalent(connection_options = nil)
          first_jump, extra_jumps = jump_proxies.split(",", 2)
          config = connection_options && connection_options[:config]
          uri = URI.parse("ssh://#{first_jump}")

          template = "ssh".dup
          template << " -l #{uri.user}"    if uri.user
          template << " -p #{uri.port}"    if uri.port
          template << " -J #{extra_jumps}" if extra_jumps
          template << " -F #{config}" if config != true && config

          # Options in the same format as the config file
          @options.each do |option|
            template << " -o #{option}"
          end

          # Include identities from SSH connection
          connection_options.fetch(:keys, []).each do |identity_file|
            template << " -i #{identity_file}"
          end
          connection_options.fetch(:key_data, []).each do |key_data|
            template << " -i #{key_data_tempfile(key_data).path}"
          end

          template << " -W %h:%p "
          template << uri.host

          @command_line_template = template
        end

        # Creates a Tempfile containing the key data
        # Tempfiles are tracked so they are not cleaned up by Ruby's GC until the Jump instance is no longer needed
        def key_data_tempfile(key_data)
          keyfile = Tempfile.new
          keyfile.write(key_data)
          keyfile.close
          @key_data_tempfiles << keyfile
          keyfile
        end
      end
    end
  end
end
