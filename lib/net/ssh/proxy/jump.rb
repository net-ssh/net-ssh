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
      #
      # ssh_config options for the jump host can be given as a Hash via
      # +options:+; each is passed to the ssh command as +-o Key=value+:
      #
      #   proxy = Net::SSH::Proxy::Jump.new('user@proxy', options: { 'StrictHostKeyChecking' => 'no' })
      #
      # Options that ssh_config allows more than once (+IdentityFile+,
      # +CertificateFile+ and +SendEnv+) take an Array and are passed once per
      # element; an empty Array passes nothing:
      #
      #   proxy = Net::SSH::Proxy::Jump.new('user@proxy', options: { 'IdentityFile' => ['~/.ssh/jump', '~/.ssh/jump_old'] })
      #
      # A +nil+ value, alone or in an Array, raises ArgumentError, as it does
      # for the options passed to Net::SSH.start; omit the option instead.
      #
      # The options apply to the first jump host only; any further hosts in
      # the chain are connected to by that host's own ssh.
      class Jump < Command
        # The jump proxies
        attr_reader :jump_proxies

        # Create a new socket factory that tunnels via multiple jump proxes as
        # [user@]host[:port].
        def initialize(jump_proxies, options: {})
          @jump_proxies = jump_proxies
          @options = options
          validate_options!
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
          template << " -F #{escape(config)}" if config != true && config
          @options.each do |key, values|
            Array(values).each { |value| template << " -o #{escape(key)}=#{escape(value)}" }
          end
          template << " -W %h:%p "
          template << escape(uri.host)

          @command_line_template = template
        end

        private

        # Like Net::SSH.start, reject nil option values (alone or in an Array)
        # rather than silently passing nothing or an empty value to ssh.
        def validate_options!
          nil_keys = @options.select { |_key, value| value.nil? || (value.is_a?(Array) && value.include?(nil)) }.keys
          return if nil_keys.empty?

          raise ArgumentError, "nil is not allowed for #{nil_keys.map(&:inspect).join(', ')} in Net::SSH::Proxy::Jump options; " \
                               "omit the option to use the default or ssh_config value"
        end

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
