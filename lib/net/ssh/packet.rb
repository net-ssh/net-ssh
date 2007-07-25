require 'net/ssh/buffer'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/connection/constants'

module Net; module SSH
  class Packet < Buffer
    @@types = {}
    def self.register(type, *pairs)
      @@types[type] = pairs
    end

    register Transport::Constants::SERVICE_ACCEPT, [:service_name, :string]

    register Authentication::Constants::USERAUTH_BANNER, [:message, :string], [:language, :string]
    register Authentication::Constants::USERAUTH_FAILURE, [:authentications, :string], [:partial_success, :bool]

    register Connection::Constants::CHANNEL_OPEN_CONFIRMATION, [:local_id, :long], [:remote_id, :long], [:window_size, :long], [:packet_size, :long]
    register Connection::Constants::CHANNEL_WINDOW_ADJUST, [:local_id, :long], [:extra_bytes, :long]
    register Connection::Constants::CHANNEL_DATA, [:local_id, :long], [:data, :string]
    register Connection::Constants::CHANNEL_EOF, [:local_id, :long]
    register Connection::Constants::CHANNEL_CLOSE, [:local_id, :long]
    register Connection::Constants::CHANNEL_REQUEST, [:local_id, :long], [:request, :string], [:want_reply, :bool], [:request_data, :buffer]

    def initialize(payload)
      @instantiated = false
      @named_elements = {}
      super
      instantiate!
    end

    def type
      @type ||= read_byte
    end

    def instantiate(*definitions)
      return if @instantiated
      @instantiated = true

      definitions.each do |name, datatype|
        @named_elements[name.to_sym] = if datatype == :buffer
          remainder_as_buffer
        else
          send("read_#{datatype}")
        end
      end

      self
    end

    def [](name)
      name = name.to_sym
      raise ArgumentError, "no such element #{name}" unless @named_elements.key?(name)
      @named_elements[name]
    end

    def instantiate!
      return unless @@types[type]
      instantiate(*@@types[type])
    end
  end
end; end