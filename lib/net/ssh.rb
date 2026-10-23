require 'logger'
require 'etc'
require 'shellwords'

require 'net/ssh/config'
require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/transport/session'
require 'net/ssh/authentication/session'
require 'net/ssh/connection/session'
require 'net/ssh/multiplex'
require 'net/ssh/prompt'

module Net
  # Net::SSH is a library for interacting, programmatically, with remote
  # processes via the SSH2 protocol. Sessions are always initiated via
  # Net::SSH.start. From there, a program interacts with the new SSH session
  # via the convenience methods on Net::SSH::Connection::Session, by opening
  # and interacting with new channels (Net::SSH::Connection:Session#open_channel
  # and Net::SSH::Connection::Channel), or by forwarding local and/or
  # remote ports through the connection (Net::SSH::Service::Forward).
  #
  # The SSH protocol is very event-oriented. Requests are sent from the client
  # to the server, and are answered asynchronously. This gives great flexibility
  # (since clients can have multiple requests pending at a time), but it also
  # adds complexity. Net::SSH tries to manage this complexity by providing
  # some simpler methods of synchronous communication (see Net::SSH::Connection::Session#exec!).
  #
  # In general, though, and if you want to do anything more complicated than
  # simply executing commands and capturing their output, you'll need to use
  # channels (Net::SSH::Connection::Channel) to build state machines that are
  # executed while the event loop runs (Net::SSH::Connection::Session#loop).
  #
  # Net::SSH::Connection::Session and Net::SSH::Connection::Channel have more
  # information about this technique.
  #
  # = "Um, all I want to do is X, just show me how!"
  #
  # == X == "execute a command and capture the output"
  #
  #   Net::SSH.start("host", "user", password: "password") do |ssh|
  #     result = ssh.exec!("ls -l")
  #     puts result
  #   end
  #
  # == X == "forward connections on a local port to a remote host"
  #
  #   Net::SSH.start("host", "user", password: "password") do |ssh|
  #     ssh.forward.local(1234, "www.google.com", 80)
  #     ssh.loop { true }
  #   end
  #
  # == X == "forward connections on a remote port to the local host"
  #
  #   Net::SSH.start("host", "user", password: "password") do |ssh|
  #     ssh.forward.remote(80, "www.google.com", 1234)
  #     ssh.loop { true }
  #   end
  module SSH
    # This is the set of options that Net::SSH.start recognizes. See
    # Net::SSH.start for a description of each option.
    VALID_OPTIONS = %i[
      auth_methods bind_address compression compression_level config
      encryption forward_agent hmac host_key identity_agent remote_user
      keepalive keepalive_interval keepalive_maxcount kex keys key_data
      keycerts keycert_data languages logger password port proxy
      rekey_blocks_limit rekey_limit rekey_packet_limit timeout verbose
      known_hosts global_known_hosts_file user_known_hosts_file host_key_alias
      host_name user properties passphrase keys_only max_pkt_size
      max_win_size send_env set_env use_agent number_of_password_prompts
      append_all_supported_algorithms non_interactive password_prompt
      agent_socket_factory minimum_dh_bits verify_host_key
      fingerprint_hash check_host_ip pubkey_algorithms no_delay
      control_master control_path preopen_channels
    ]

    # The standard means of starting a new SSH connection. When used with a
    # block, the connection will be closed when the block terminates, otherwise
    # the connection will just be returned. The yielded (or returned) value
    # will be an instance of Net::SSH::Connection::Session (q.v.). (See also
    # Net::SSH::Connection::Channel and Net::SSH::Service::Forward.)
    #
    #   Net::SSH.start("host", "user") do |ssh|
    #     ssh.exec! "cp /some/file /another/location"
    #     hostname = ssh.exec!("hostname")
    #
    #     ssh.open_channel do |ch|
    #       ch.exec "sudo -p 'sudo password: ' ls" do |ch, success|
    #         abort "could not execute sudo ls" unless success
    #
    #         ch.on_data do |ch, data|
    #           print data
    #           if data =~ /sudo password: /
    #             ch.send_data("password\n")
    #           end
    #         end
    #       end
    #     end
    #
    #     ssh.loop
    #   end
    #
    # This method accepts the following options (all are optional). Omit an
    # option to use its default or ssh_config value; passing +nil+ (or an array
    # containing +nil+) raises ArgumentError, except for :password,
    # :passphrase, :logger and :password_prompt, where +nil+ means the default.
    #
    # * :auth_methods => an array of authentication methods to try
    # * :bind_address => the IP address on the connecting machine to use in
    #   establishing connection. (:bind_address is discarded if :proxy
    #   is set.)
    # * :check_host_ip => Also check IP address when connecting to remote host.
    #   Defaults to +true+.
    # * :compression => the compression algorithm to use, or +true+ to use
    #   whatever is supported.
    # * :compression_level => the compression level to use when sending data
    # * :control_master => set to +:auto+ to run the session through an
    #   already running OpenSSH ControlMaster for the same host, port and user
    #   (started e.g. with <tt>ssh -M</tt> or <tt>ControlMaster auto</tt>),
    #   using its proxy mode (OpenSSH 7.4 or later). This skips the TCP
    #   connection, key exchange and authentication. If there is no usable
    #   master (no ControlPath, no socket, refused, timed out, owned by another
    #   user) Net::SSH logs why and connects as usual; it never starts a master
    #   itself. The master's own settings then apply instead of the options
    #   for setting up a connection (:keys, :key_data, :password, :passphrase,
    #   :auth_methods, :verify_host_key, :known_hosts, :host_key, :kex,
    #   :encryption, :hmac, :compression, :rekey_*, :proxy, :keepalive and the
    #   like); explicitly passed ones are named at info level. Over the
    #   master, remote port forwarding (Service::Forward#remote and
    #   #cancel_remote) raises Net::SSH::NotSupportedOverControlMaster, as the
    #   master consumes the global request reply, so success, failure and the
    #   port allocated for port 0 can't be observed; other global requests
    #   raise it too. Agent and X11 forwarding requests raise it
    #   too, and :forward_agent is ignored (logged at info level), because the
    #   master serves them from its own agent or display only if it has
    #   ForwardAgent or ForwardX11 enabled itself, and rejects them otherwise.
    #   Keepalive and rekeying are left to the master. ssh_config's
    #   ControlMaster is ignored, only this option enables it. An invalid
    #   ControlPath raises ArgumentError. A missing or stale socket is logged
    #   at info level, a socket that can't be used (another owner, refused,
    #   wrong protocol, timed out) at warn level. Has no effect on Windows.
    #   Defaults to +false+.
    # * :control_path => the ControlMaster socket to use with
    #   :control_master, with the same ~, ${ENV} and % tokens as ssh_config's
    #   ControlPath (%C, %d, %h, %i, %j, %k, %L, %l, %n, %p, %r, %u, %%).
    #   The master at that path decides which host and user the session is
    #   connected to, so a fixed path without %h, %p, %r or %C sends every
    #   host through the same master and the explicitly passed host key and
    #   authentication options are ignored. Defaults to ControlPath from
    #   ssh_config; +"none"+ disables the master.
    # * :config => set to +true+ to load the default OpenSSH config files
    #   (~/.ssh/config, /etc/ssh_config), or to +false+ to not load them, or to
    #   a file-name (or array of file-names) to load those specific configuration
    #   files. Defaults to +true+.
    # * :encryption => the encryption cipher (or ciphers) to use
    # * :forward_agent => set to true if you want the SSH agent connection to
    #   be forwarded. Ignored for a session through a ControlMaster (see
    #   :control_master).
    # * :known_hosts => a custom object holding known hosts records.
    #   It must implement #search_for and `add` in a similiar manner as KnownHosts.
    # * :global_known_hosts_file => the location of the global known hosts
    #   file. Set to an array if you want to specify multiple global known
    #   hosts files. Defaults to %w(/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2).
    # * :hmac => the hmac algorithm (or algorithms) to use
    # * :host_key => the host key algorithm (or algorithms) to use
    # * :host_key_alias => the host name to use when looking up or adding a
    #   host to a known_hosts dictionary file
    # * :host_name => the real host name or IP to log into. This is used
    #   instead of the +host+ parameter, and is primarily only useful when
    #   specified in an SSH configuration file. It lets you specify an
    #   "alias", similarly to adding an entry in /etc/hosts but without needing
    #   to modify /etc/hosts.
    # * :keepalive => set to +true+ to send a keepalive packet to the SSH server
    #   when there's no traffic between the SSH server and Net::SSH client for
    #   the keepalive_interval seconds. Defaults to +false+.
    # * :keepalive_interval => the interval seconds for keepalive.
    #   Defaults to +300+ seconds.
    # * :keepalive_maxcount => the maximun number of keepalive packet miss allowed.
    #   Defaults to 3
    # * :kex => the key exchange algorithm (or algorithms) to use. Like
    #   KexAlgorithms, entries starting with +, - or ^ modify the default list.
    #   diffie-hellman-group14-sha1 is supported but not offered unless listed
    #   here (e.g. '+diffie-hellman-group14-sha1') or
    #   :append_all_supported_algorithms is set.
    # * :keys => an array of file names of private keys to use for publickey
    #   and hostbased authentication
    # * :keycerts => an array of file names of key certificates to use
    #    with publickey authentication
    # * :keycert_data => an array of strings, which each element of the array
    #   being a key certificate to use with publickey authentication
    # * :key_data => an array of strings, with each element of the array being
    #   a raw private key in PEM format.
    # * :keys_only => set to +true+ to use only private keys from +keys+ and
    #   +key_data+ parameters, even if ssh-agent offers more identities. This
    #   option is intended for situations where ssh-agent offers many different
    #   identites.
    # * :logger => the logger instance to use when logging
    # * :max_pkt_size => maximum size we tell the other side that is supported per
    #   packet. Default is 0x8000 (32768 bytes). Increase to 0x10000 (65536 bytes)
    #   for better performance if your SSH server supports it (most do).
    # * :max_win_size => maximum size we tell the other side that is supported for
    #   the window, i.e. how much the server may send on a channel before net-ssh
    #   reads it. Default is 0x200000 (2 MB), as in OpenSSH. Smaller values limit
    #   how much data is in flight; some servers (e.g. Mikrotik) truncate output
    #   when the window is small.
    # * :minimum_dh_bits => the smallest group, in bits, accepted from the server
    #   in diffie-hellman-group-exchange key exchange. Defaults to 2048, as in
    #   OpenSSH; lower it (e.g. to 1024) only to reach legacy servers that offer
    #   nothing larger.
    # * :no_delay => turns Nagle's algorithm off on the connection's socket
    #   (TCP_NODELAY), so a packet written while the previous one is still
    #   unacknowledged is sent right away instead of waiting for the server's
    #   ACK. OpenSSH does the same for every connection. Set to +false+ to keep
    #   Nagle's algorithm on. Has no effect when the socket comes from a
    #   ProxyCommand, whose command owns the TCP connection. Defaults to +true+.
    # * :non_interactive => set to true if your app is non interactive and prefers
    #   authentication failure vs password prompt. Non-interactive applications
    #   should set it to true to prefer failing a password/etc auth methods vs.
    #   asking for password.
    # * :passphrase => the passphrase to use when loading a private key (default
    #   is +nil+, for no passphrase)
    # * :password => the password to use to login
    # * :port => the port to use when connecting to the remote host
    # * :preopen_channels => set to +true+ to keep one spare "session" channel
    #   open, so that Net::SSH::Connection::Session#open_channel can hand it
    #   out at once and a command that waits for the previous one to finish
    #   costs one round trip instead of two. The spare counts against the
    #   server's MaxSessions; if the server refuses it, pre-opening stops for
    #   the session. Defaults to +false+.
    # * :properties => a hash of key/value pairs to add to the new connection's
    #   properties (see Net::SSH::Connection::Session#properties)
    # * :proxy => a proxy instance (see Proxy) to use when connecting
    # * :pubkey_algorithms => the public key authentication algorithms to offer,
    #   in order of preference (e.g. %w[ssh-ed25519 rsa-sha2-512 rsa-sha2-256]).
    #   Keys whose type isn't listed are skipped. Like PubkeyAcceptedAlgorithms,
    #   entries starting with +, - or ^ modify the default list. ssh-rsa (SHA-1),
    #   ssh-rsa-cert-v01@openssh.com and ssh-dss are supported but not offered
    #   unless listed here (e.g. '+ssh-rsa') or :append_all_supported_algorithms
    #   is set.
    # * :rekey_blocks_limit => the max number of blocks to process before rekeying
    # * :rekey_limit => the max number of bytes to process before rekeying
    # * :rekey_packet_limit => the max number of packets to process before rekeying
    # * :send_env => an array of local environment variable names to export to the
    #   remote environment. Names may be given as String or Regexp.
    # * :set_env => a hash of environment variable names and values to set to the
    #   remote environment. Override the ones if specified in +send_env+.
    # * :timeout => how long to wait for the initial connection to be made
    # * :user => the user name to log in as; this overrides the +user+
    #   parameter, and is primarily only useful when provided via an SSH
    #   configuration file.
    # * :remote_user => used for substitution into the '%r' part of a ProxyCommand;
    #   defaults to the user name the connection logs in as.
    # * :user_known_hosts_file => the location of the user known hosts file.
    #   Set to an array to specify multiple user known hosts files.
    #   Defaults to %w(~/.ssh/known_hosts ~/.ssh/known_hosts2).
    # * :use_agent => Set false to disable the use of ssh-agent. Defaults to
    #   true
    # * :identity_agent => the path to the ssh-agent's UNIX socket
    # * :verbose => how verbose to be (Logger verbosity constants, Logger::DEBUG
    #   is very verbose, Logger::FATAL is all but silent). Logger::FATAL is the
    #   default. The symbols :debug, :info, :warn, :error, and :fatal are also
    #   supported and are translated to the corresponding Logger constant.
    # * :append_all_supported_algorithms => set to +true+ to append all supported
    #   algorithms by net-ssh, except the +none+ cipher and MAC, which must be
    #   named explicitly (e.g. encryption: '+none'). Was the default behaviour
    #   until 2.10
    # * :number_of_password_prompts => Number of prompts for the password
    #   authentication method defaults to 3 set to 0 to disable prompt for
    #   password auth method
    # * :password_prompt => a custom prompt object with ask method. See Net::SSH::Prompt
    #
    # * :agent_socket_factory => enables the user to pass a lambda/block that will serve as the socket factory
    #    Net::SSH.start(host,user,agent_socket_factory: ->{ UNIXSocket.open('/foo/bar') })
    #    example: ->{ UNIXSocket.open('/foo/bar')}
    # * :verify_host_key => specify how strict host-key verification should be.
    #   In order of increasing strictness:
    #   * :never (very insecure) ::Net::SSH::Verifiers::Never
    #   * :accept_new_or_local_tunnel (insecure) ::Net::SSH::Verifiers::AcceptNewOrLocalTunnel
    #   * :accept_new (insecure) ::Net::SSH::Verifiers::AcceptNew
    #   * :always (secure) ::Net::SSH::Verifiers::Always
    #   You can also provide an own Object which responds to +verify+ and
    #   +verify_signature+. The argument given to +verify+ is a hash consisting
    #   of the +:key+, the +:key_blob+, the +:fingerprint+ and the +:session+.
    #   Returning true accepts the host key, returning false declines it and
    #   closes the connection. +verify_signature+ is given a block that checks
    #   the server's host key signature and must return the block's result.
    # * :fingerprint_hash => 'MD5' or 'SHA256', defaults to 'SHA256'
    # If +user+ parameter is nil it defaults to USER from ssh_config, or
    # local username
    def self.start(host, user = nil, options = {}, &block)
      if options.key?(:paranoid)
        raise ArgumentError, ":paranoid has been removed, use :verify_host_key (same values)"
      end

      invalid_options = options.keys - VALID_OPTIONS
      if invalid_options.any?
        raise ArgumentError, "invalid option(s): #{invalid_options.join(', ')}"
      end

      reject_nil_options(options)
      Multiplex.validate_options!(options)
      explicit_options = options.keys
      host_arg = host

      options = options.dup
      assign_defaults(options)

      options[:user] = user if user
      options = configuration_for(host, options.fetch(:config, true)).merge(options)
      host = options.fetch(:host_name, host)

      options[:check_host_ip] = true unless options.key?(:check_host_ip)

      if options[:non_interactive]
        options[:number_of_password_prompts] = 0
      end

      if options[:verbose]
        options[:logger].level = case options[:verbose]
                                 when Integer then options[:verbose]
                                 when :debug then Logger::DEBUG
                                 when :info  then Logger::INFO
                                 when :warn  then Logger::WARN
                                 when :error then Logger::ERROR
                                 when :fatal then Logger::FATAL
                                 else raise ArgumentError, "can't convert #{options[:verbose].inspect} to any of the Logger level constants"
                                 end
      end

      user = options.fetch(:user, user) || Etc.getpwuid.name
      options[:remote_user] ||= user

      connection = Multiplex.connect(host_arg, host, user, options, explicit: explicit_options) if options[:control_master]
      connection ||= connect_directly(host, user, options)

      if block_given?
        begin
          yield connection
        ensure
          connection.close unless connection.closed?
        end
      else
        connection
      end
    end

    def self.connect_directly(host, user, options)
      transport = Transport::Session.new(host, options)
      auth = Authentication::Session.new(transport, options)

      unless auth.authenticate("ssh-connection", user, options[:password])
        transport.close
        raise AuthenticationFailed, "Authentication failed for user #{user}@#{host}"
      end

      Connection::Session.new(transport, options)
    end
    private_class_method :connect_directly

    # Returns a hash of the configuration options for the given host, as read
    # from the SSH configuration file(s). If +use_ssh_config+ is true (the
    # default), this will load configuration from both ~/.ssh/config and
    # /etc/ssh_config. If +use_ssh_config+ is nil or false, nothing will be
    # loaded (and an empty hash returned). Otherwise, +use_ssh_config+ may
    # be a file name (or array of file names) of SSH configuration file(s)
    # to read.
    #
    # See Net::SSH::Config for the full description of all supported options.
    def self.configuration_for(host, use_ssh_config)
      files = case use_ssh_config
              when true then Net::SSH::Config.expandable_default_files
              when false, nil then return {}
              else Array(use_ssh_config)
              end

      Net::SSH::Config.for(host, files)
    end

    def self.assign_defaults(options)
      if !options[:logger]
        options[:logger] = Logger.new(STDERR)
        options[:logger].level = Logger::FATAL
      end

      options[:password_prompt] ||= Prompt.default(options)

      %i[password passphrase].each do |key|
        options.delete(key) if options.key?(key) && options[key].nil?
      end
    end

    NIL_ALLOWED_OPTIONS = %i[password passphrase logger password_prompt].freeze

    NIL_OPTION_HINTS = {
      config: "config: false to skip ssh_config files",
      proxy: "proxy: false to connect without a proxy",
      keys: "keys: [] to use no key files",
      use_agent: "use_agent: false to not use ssh-agent",
      forward_agent: "forward_agent: false to not forward ssh-agent",
      keepalive: "keepalive: false to send no keepalives",
      compression: "compression: false to disable compression",
      control_master: "control_master: false to not use a ControlMaster",
      control_path: "control_path: 'none' to not use a ControlMaster socket",
      send_env: "send_env: [] to send no environment variables",
      set_env: "set_env: {} to set no environment variables"
    }.freeze
    private_constant :NIL_ALLOWED_OPTIONS, :NIL_OPTION_HINTS

    def self.reject_nil_options(options)
      nil_keys = options.select do |key, value|
        !NIL_ALLOWED_OPTIONS.include?(key) && (value.nil? || (value.is_a?(Array) && value.include?(nil)))
      end.keys
      return if nil_keys.empty?

      message = "nil is not allowed for #{nil_keys.map(&:inspect).join(', ')}; " \
                "omit #{nil_keys.one? ? 'it' : 'them'} to use the default or ssh_config value"
      hints = NIL_OPTION_HINTS.values_at(*nil_keys).compact
      message += ", or pass #{hints.join(', or ')}" if hints.any?
      raise ArgumentError, message
    end
    private_class_method :reject_nil_options
  end
end
