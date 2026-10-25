require 'shellwords'
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
      #   proxy = Net::SSH::Proxy::Jump.new('user@proxy')
      #   Net::SSH.start('host', 'user', :proxy => proxy) do |ssh|
      #     ...
      #   end
      class Jump < Command
        # The jump proxies
        attr_reader :jump_proxies

        # Create a new socket factory that tunnels via multiple jump proxes as
        # [user@]host[:port].
        def initialize(jump_proxies)
          @jump_proxies = jump_proxies
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
          raise ArgumentError, "no jump host given" if jump_proxies.empty?

          config = connection_options && connection_options[:config]
          uri, *extra_jumps = jump_proxies.split(",", -1).map { |jump| validate_jump!(jump) }

          template = "ssh".dup
          template << " -l #{escape(uri.user)}" if uri.user
          template << " -p #{uri.port}" if uri.port
          template << " -J #{escape(extra_jumps.map { |jump| jump_spec(jump) }.join(','))}" unless extra_jumps.empty?
          template << " -F #{Shellwords.escape(config)}" if config != true && config
          template << " -W %h:%p "
          template << escape(uri.host)

          @command_line_template = template
        end

        private

        # Escape for the shell, and double any % so it survives the %h/%p
        # substitution done on the template in Command#open.
        def escape(value)
          Shellwords.escape(value).gsub("%", "%%")
        end

        # Only [user@]host[:port] is checked, so anything else URI accepts (a path,
        # query, fragment or password) must be refused before it reaches the shell.
        def validate_jump!(jump)
          uri = URI.parse("ssh://#{jump}")
          raise URI::InvalidURIError if uri.host.to_s.empty? || jump_spec(uri) != jump

          validate_user_name!(uri.user) if uri.user
          validate_host_name!(uri.host)
          validate_port!(uri.port) if uri.port
          uri
        rescue URI::InvalidURIError
          raise ArgumentError, "jump host is not [user@]host[:port]: #{jump.inspect}"
        end

        def jump_spec(uri)
          spec = uri.host.dup
          spec.prepend("#{uri.user}@") if uri.user
          spec << ":#{uri.port}" if uri.port
          spec
        end
      end
    end
  end
end
