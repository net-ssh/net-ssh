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

    attr_reader :session

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

    def self.negotiate_via(session)
      new(session).renegotiate!
    end

    def initialize(session)
      @session = session
      @logger = session.logger
      @algorithms = {}
      prepare_preferred_algorithms!
    end

    def renegotiate!
      trace { "negotiating algorithms" }
      server_data = parse_server_algorithm_packet
      client_data = build_client_algorithm_packet

      session.send_message(client_data)

      @server_packet = server_data[:raw]
      @client_packet = client_data.to_s

      negotiate_algorithms_from(server_data)

      exchange_keys

      self
    end

    def [](key)
      @algorithms[key]
    end

    private

      def prepare_preferred_algorithms!
        @algorithms = {
          :host_key    => %w(ssh-dss ssh-rsa),
          :kex         => %w(diffie-hellman-group-exchange-sha1
                             diffie-hellman-group1-sha1),
          :encryption  => %w(aes128-cbc 3des-cbc blowfish-cbc aes256-cbc
                             aes192-cbc idea-cbc none),
          :hmac        => %w(hmac-sha1 hmac-md5 hmac-sha1-96 hmac-md5-96 none),
          :compression => %w(none),
          :languages   => %w() 
        }

        # for convention, make sure our list has the same keys as the server
        # list

        @algorithms[:encryption_client ] = @algorithms[:encryption_server ] = @algorithms[:encryption]
        @algorithms[:hmac_client       ] = @algorithms[:hmac_server       ] = @algorithms[:hmac]
        @algorithms[:compression_client] = @algorithms[:compression_server] = @algorithms[:compression]
        @algorithms[:language_client   ] = @algorithms[:language_server   ] = @algorithms[:languages]

        # make sure the host keys are specified in preference order, where any
        # existing known key for the host has preference.

        existing_keys = KnownHosts.search_in(["#{ENV['HOME']}/.ssh/known_hosts"], session.host_as_string)
        host_keys = existing_keys.map { |key| key.ssh_type }.uniq
        @algorithms[:host_key].each do |name|
          host_keys << name unless host_keys.include?(name)
        end
        @algorithms[:host_key] = host_keys
      end

      def parse_server_algorithm_packet
        data = {}

        buffer = session.next_message
        raise Net::SSH::Exception, "expected KEXINIT" unless buffer.type == KEXINIT

        data[:raw] = buffer.content

        buffer.read(16) # skip the cookie value

        data[:kex]                = buffer.read_string.split(/,/)
        data[:host_key]           = buffer.read_string.split(/,/)
        data[:encryption_client]  = buffer.read_string.split(/,/)
        data[:encryption_server]  = buffer.read_string.split(/,/)
        data[:hmac_client]        = buffer.read_string.split(/,/)
        data[:hmac_server]        = buffer.read_string.split(/,/)
        data[:compression_client] = buffer.read_string.split(/,/)
        data[:compression_server] = buffer.read_string.split(/,/)
        data[:language_client]    = buffer.read_string.split(/,/)
        data[:language_server]    = buffer.read_string.split(/,/)

        # TODO: if first_kex_packet_follows, we need to try to skip the
        # actual kexinit stuff and try to guess what the server is doing...
        # need to read more about this scenario.
        first_kex_packet_follows = buffer.read_bool

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

      def negotiate_algorithms_from(server_data)
        @kex                = negotiate(:kex, server_data)
        @host_key           = negotiate(:host_key, server_data)
        @encryption_client  = negotiate(:encryption_client, server_data)
        @encryption_server  = negotiate(:encryption_server, server_data)
        @hmac_client        = negotiate(:hmac_client, server_data)
        @hmac_server        = negotiate(:hmac_server, server_data)
        @compression_client = negotiate(:compression_client, server_data)
        @compression_server = negotiate(:compression_server, server_data)
        @language_client    = negotiate(:language_client, server_data) rescue ""
        @language_server    = negotiate(:language_server, server_data) rescue ""

        trace do
          "negotiated:\n" +
            [:kex, :host_key, :encryption_server, :encryption_client, :hmac_client, :hmac_server, :compression_client, :compression_server, :language_client, :language_server].map do |key|
              "* #{key}: #{instance_variable_get("@#{key}")}"
            end.join("\n")
        end
      end

      def negotiate(algorithm, server_data)
        match = self[algorithm].find { |item| server_data[algorithm].include?(item) }

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

        session.socket.client_cipher = cipher_client
        session.socket.server_cipher = cipher_server
        session.socket.client_hmac   = mac_client
        session.socket.server_hmac   = mac_server
      end
  end
end; end; end