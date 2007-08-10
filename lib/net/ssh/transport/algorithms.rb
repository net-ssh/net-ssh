require 'net/ssh/buffer'
require 'net/ssh/known_hosts'
require 'net/ssh/loggable'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/hmac'
require 'net/ssh/transport/kex'

module Net; module SSH; module Transport
  class Algorithms
    include Constants, Loggable

    ALGORITHMS = {
      :host_key    => %w(ssh-rsa ssh-dss),
      :kex         => %w(diffie-hellman-group-exchange-sha1
                         diffie-hellman-group1-sha1),
      :encryption  => %w(aes128-cbc 3des-cbc blowfish-cbc cast128-cbc
                         aes192-cbc aes256-cbc rijndael-cbc@lysator.liu.se
                         idea-cbc none),
      :hmac        => %w(hmac-sha1 hmac-md5 hmac-sha1-96 hmac-md5-96 none),
      :compression => %w(none zlib@openssh.com zlib),
      :languages   => %w() 
    }

    attr_reader :session
    attr_reader :options

    attr_reader :kex
    attr_reader :host_key
    attr_reader :encryption_client
    attr_reader :encryption_server
    attr_reader :hmac_client
    attr_reader :hmac_server
    attr_reader :compression_client
    attr_reader :compression_server
    attr_reader :language_client
    attr_reader :language_server

    attr_reader :session_id

    # Returns true if the given packet can be processed during a key-exchange
    def self.allowed_packet?(packet)
      ( 1.. 4).include?(packet.type) ||
      ( 6..19).include?(packet.type) ||
      (21..49).include?(packet.type)
    end

    def initialize(session, options={})
      @session = session
      @logger = session.logger
      @options = options
      @algorithms = {}
      @pending = @initialized = false
      @client_packet = @server_packet = nil
      prepare_preferred_algorithms!
    end

    def rekey!
      @client_packet = @server_packet = nil
      @initialized = false
      send_kexinit
    end

    def accept_kexinit(packet)
      trace { "got KEXINIT from server" }
      @server_data = parse_server_algorithm_packet(packet)
      @server_packet = @server_data[:raw]
      if !pending?
        send_kexinit
      else
        @pending = true
        proceed!
      end
    end

    def [](key)
      @algorithms[key]
    end

    def pending?
      @pending
    end

    def allow?(packet)
      !pending? || Algorithms.allowed_packet?(packet)
    end

    def initialized?
      @initialized
    end

    private

      def send_kexinit
        trace { "sending KEXINIT" }
        @pending = true
        packet = build_client_algorithm_packet
        @client_packet = packet.to_s
        session.send_message(packet)
        proceed! if @server_packet
      end

      def proceed!
        trace { "negotiating algorithms" }
        negotiate_algorithms
        exchange_keys
        @pending = false
      end

      def prepare_preferred_algorithms!
        options[:compression] = %w(zlib@openssh.com zlib) if options[:compression] == true

        ALGORITHMS.each do |algorithm, list|
          @algorithms[algorithm] = list.dup

          # apply the preferred algorithm order, if any
          if options[algorithm]
            @algorithms[algorithm] = Array(options[algorithm]).compact.uniq
            invalid = @algorithms[algorithm].detect { |name| !ALGORITHMS[algorithm].include?(name) }
            raise NotImplementedError, "unsupported #{algorithm} algorithm: `#{invalid}'" if invalid

            # make sure all of our supported algorithms are tacked onto the
            # end, so that if the user tries to give a list of which none are
            # supported, we can still proceed.
            list.each { |name| @algorithms[algorithm] << name unless @algorithms[algorithm].include?(name) }
          end
        end

        # for convention, make sure our list has the same keys as the server
        # list

        @algorithms[:encryption_client ] = @algorithms[:encryption_server ] = @algorithms[:encryption]
        @algorithms[:hmac_client       ] = @algorithms[:hmac_server       ] = @algorithms[:hmac]
        @algorithms[:compression_client] = @algorithms[:compression_server] = @algorithms[:compression]
        @algorithms[:language_client   ] = @algorithms[:language_server   ] = @algorithms[:languages]

        if !options.key?(:host_key)
          # make sure the host keys are specified in preference order, where any
          # existing known key for the host has preference.

          existing_keys = KnownHosts.search_for(session.host_as_string)
          host_keys = existing_keys.map { |key| key.ssh_type }.uniq
          @algorithms[:host_key].each do |name|
            host_keys << name unless host_keys.include?(name)
          end
          @algorithms[:host_key] = host_keys
        end
      end

      def parse_server_algorithm_packet(packet)
        data = { :raw => packet.content }

        packet.read(16) # skip the cookie value

        data[:kex]                = packet.read_string.split(/,/)
        data[:host_key]           = packet.read_string.split(/,/)
        data[:encryption_client]  = packet.read_string.split(/,/)
        data[:encryption_server]  = packet.read_string.split(/,/)
        data[:hmac_client]        = packet.read_string.split(/,/)
        data[:hmac_server]        = packet.read_string.split(/,/)
        data[:compression_client] = packet.read_string.split(/,/)
        data[:compression_server] = packet.read_string.split(/,/)
        data[:language_client]    = packet.read_string.split(/,/)
        data[:language_server]    = packet.read_string.split(/,/)

        # TODO: if first_kex_packet_follows, we need to try to skip the
        # actual kexinit stuff and try to guess what the server is doing...
        # need to read more about this scenario.
        first_kex_packet_follows = packet.read_bool

        return data
      end

      def build_client_algorithm_packet
        kex         = @algorithms[:kex        ].join(",")
        host_key    = @algorithms[:host_key   ].join(",")
        encryption  = @algorithms[:encryption ].join(",")
        hmac        = @algorithms[:hmac       ].join(",")
        compression = @algorithms[:compression].join(",")
        languages   = @algorithms[:languages  ].join(",")

        msg = Net::SSH::Buffer.new
        msg.write_byte KEXINIT
        msg.write_long rand(0xFFFFFFFF), rand(0xFFFFFFFF), rand(0xFFFFFFFF), rand(0xFFFFFFFF)
        msg.write_string kex, host_key
        msg.write_string encryption, encryption
        msg.write_string hmac, hmac
        msg.write_string compression, compression
        msg.write_string languages, languages
        msg.write_bool false
        msg.write_long 0
  
        return msg
      end

      def negotiate_algorithms
        @kex                = negotiate(:kex)
        @host_key           = negotiate(:host_key)
        @encryption_client  = negotiate(:encryption_client)
        @encryption_server  = negotiate(:encryption_server)
        @hmac_client        = negotiate(:hmac_client)
        @hmac_server        = negotiate(:hmac_server)
        @compression_client = negotiate(:compression_client)
        @compression_server = negotiate(:compression_server)
        @language_client    = negotiate(:language_client) rescue ""
        @language_server    = negotiate(:language_server) rescue ""

        trace do
          "negotiated:\n" +
            [:kex, :host_key, :encryption_server, :encryption_client, :hmac_client, :hmac_server, :compression_client, :compression_server, :language_client, :language_server].map do |key|
              "* #{key}: #{instance_variable_get("@#{key}")}"
            end.join("\n")
        end
      end

      def negotiate(algorithm)
        match = self[algorithm].find { |item| @server_data[algorithm].include?(item) }

        if match.nil?
          raise Net::SSH::Exception, "could not settle on #{algorithm} algorithm"
        end

        return match
      end

      def kex_byte_requirement
        sizes = []

        sizes.concat(CipherFactory.get_lengths(encryption_client))
        sizes.concat(CipherFactory.get_lengths(encryption_server))

        sizes << HMAC.key_length(hmac_client)
        sizes << HMAC.key_length(hmac_server)

        sizes.max
      end

      def exchange_keys
        trace { "exchanging keys" }

        algorithm = Kex::MAP[kex].new(self, session,
          :client_version_string => Net::SSH::Transport::ServerVersion::PROTO_VERSION,
          :server_version_string => session.server_version.version,
          :server_algorithm_packet => @server_packet,
          :client_algorithm_packet => @client_packet,
          :need_bytes => kex_byte_requirement,
          :logger => logger)
        result = algorithm.exchange_keys

        secret   = result[:shared_secret].to_ssh
        hash     = result[:session_id]
        digester = result[:hashing_algorithm]

        @session_id ||= hash

        key = Proc.new { |salt| digester.digest(secret + hash + salt + @session_id) }
        
        iv_client = key["A"]
        iv_server = key["B"]
        key_client = key["C"]
        key_server = key["D"]
        mac_key_client = key["E"]
        mac_key_server = key["F"]

        parameters = { :iv => iv_client, :key => key_client, :shared => secret,
          :hash => hash, :digester => digester }
        
        cipher_client = CipherFactory.get(encryption_client, parameters.merge(:encrypt => true))
        cipher_server = CipherFactory.get(encryption_server, parameters.merge(:iv => iv_server, :key => key_server, :decrypt => true))

        mac_client = HMAC.get(hmac_client, mac_key_client)
        mac_server = HMAC.get(hmac_server, mac_key_server)

        session.socket.client.set :cipher => cipher_client, :hmac => mac_client,
          :compression => normalize_compression_name(compression_client),
          :compression_level => options[:compression_level],
          :rekey_limit => options[:rekey_limit],
          :max_packets => options[:rekey_packet_limit],
          :max_blocks => options[:rekey_blocks_limit]

        session.socket.server.set :cipher => cipher_server, :hmac => mac_server,
          :compression => normalize_compression_name(compression_server),
          :rekey_limit => options[:rekey_limit],
          :max_packets => options[:rekey_packet_limit],
          :max_blocks  => options[:rekey_blocks_limit]

        @initialized = true
      end

      def normalize_compression_name(name)
        case name
        when "none"             then false
        when "zlib"             then :standard
        when "zlib@openssh.com" then :delayed
        else raise ArgumentError, "unknown compression type `#{name}'"
        end
      end
  end
end; end; end