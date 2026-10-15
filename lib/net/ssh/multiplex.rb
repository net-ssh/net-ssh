require 'socket'

require 'net/ssh/errors'
require 'net/ssh/connection/session'
require 'net/ssh/multiplex/client'
require 'net/ssh/multiplex/control_path'
require 'net/ssh/multiplex/proxy_transport'

module Net
  module SSH
    # Reuse of an existing OpenSSH ControlMaster connection, enabled by the
    # :control_master option of Net::SSH.start. Net::SSH only ever connects to
    # a master someone else started (e.g. with ssh -M or ControlMaster auto);
    # it never becomes one.
    module Multiplex
      # Used for the mux handshake when the :timeout option isn't set.
      DEFAULT_TIMEOUT = 5

      # Options for setting up a connection, which the master already did
      # with its own settings.
      MASTER_OWNED_OPTIONS = %i[
        agent_socket_factory append_all_supported_algorithms auth_methods
        bind_address check_host_ip compression compression_level encryption
        fingerprint_hash global_known_hosts_file hmac host_key identity_agent
        keepalive keepalive_interval keepalive_maxcount kex key_data keycert_data
        keycerts keys keys_only known_hosts languages minimum_dh_bits no_delay
        non_interactive number_of_password_prompts passphrase password
        password_prompt proxy pubkey_algorithms rekey_blocks_limit rekey_limit
        rekey_packet_limit use_agent user_known_hosts_file verify_host_key
      ].freeze

      VALUES = [:auto, false, nil].freeze

      def self.validate_options!(options)
        unless VALUES.include?(options[:control_master])
          raise ArgumentError, "control_master must be :auto or false, got #{options[:control_master].inspect}"
        end
        return unless options[:control_master] && options[:forward_agent]

        raise ArgumentError, "forward_agent can't be used with control_master, the ControlMaster can't forward the agent to Net::SSH"
      end

      # Returns a Connection::Session running through the ControlMaster for
      # this connection, or nil (after logging why) when there is no usable
      # master, in which case the caller connects as usual. +explicit+ are
      # the option names the caller passed to Net::SSH.start.
      def self.connect(host_arg, host, user, options, explicit: [])
        logger = options[:logger]
        path = socket_path(host_arg, host, user, options)
        return nil unless path

        socket = Client.new(path, timeout: options[:timeout] || DEFAULT_TIMEOUT, logger: logger).connect_proxy
        logger.info { "control_master: using ControlMaster at #{path}" }
        warn_master_owned(logger, explicit)
        transport = ProxyTransport.new(socket, host: host, control_path: path, options: options)
        Connection::Session.new(transport, session_options(logger, options))
      rescue Multiplex::Error, SystemCallError, IOError, ArgumentError, SocketError => e
        socket&.close
        logger.info { "control_master: not using ControlMaster#{" at #{path}" if path}: #{e.message} (#{e.class})" }
        nil
      end

      def self.socket_path(host_arg, host, user, options)
        if Gem.win_platform? || !defined?(UNIXSocket)
          options[:logger].debug { "control_master: UNIX sockets are not available on this platform" }
          return nil
        end

        control_path = options[:control_path]
        if control_path.nil? || control_path.to_s == 'none'
          options[:logger].debug { "control_master: no ControlPath set" }
          return nil
        end

        ControlPath.new(
          host_arg: host_arg, host: host, port: options[:port] || ProxyTransport::DEFAULT_PORT, remote_user: user,
          jump_host: jump_host(options[:proxy]), host_key_alias: options[:host_key_alias]
        ).expand(control_path.to_s)
      end

      def self.jump_host(proxy)
        return '' unless defined?(Net::SSH::Proxy::Jump) && proxy.is_a?(Net::SSH::Proxy::Jump)

        ControlPath.jump_host(proxy.jump_proxies)
      end

      def self.warn_master_owned(logger, explicit)
        bypassed = explicit & MASTER_OWNED_OPTIONS
        return if bypassed.empty?

        logger.warn { "control_master: ignoring #{bypassed.join(', ')}, the ControlMaster's own settings apply" }
      end

      # Keepalive is a global request, which the master doesn't allow; it
      # watches its own connection anyway. ForwardAgent from ssh_config is
      # dropped as the master can't forward the agent to Net::SSH.
      def self.session_options(logger, options)
        logger.info { "control_master: keepalive is left to the ControlMaster" } if options[:keepalive]
        logger.info { "control_master: agent forwarding is not available through the ControlMaster" } if options[:forward_agent]
        options.merge(keepalive: false, forward_agent: false)
      end

      private_class_method :socket_path, :jump_host, :warn_master_owned, :session_options
    end
  end
end
