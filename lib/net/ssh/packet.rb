require 'net/ssh/buffer'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/connection/constants'

module Net; module SSH

  # A specialization of Buffer that knows the format of certain common
  # packet types. It auto-parses those packet types, and allows them to
  # be accessed via the #[] accessor.
  class Packet < Buffer
    @@types = {}

    # Register a new packet type. The +pairs+ parameter must be either empty,
    # or an array of two-element tuples, where the first element of each
    # tuple is the name of the field, and the second is the type.
    #
    #  register DISCONNECT, [:reason_code, :long], [:description, :string], [:language, :string]
    def self.register(type, *pairs)
      @@types[type] = pairs
    end

    register Transport::Constants::DISCONNECT,     [:reason_code, :long], [:description, :string], [:language, :string]
    register Transport::Constants::IGNORE,         [:data, :string]
    register Transport::Constants::UNIMPLEMENTED,  [:number, :long]
    register Transport::Constants::DEBUG,          [:always_display, :bool], [:message, :string], [:language, :string]
    register Transport::Constants::SERVICE_ACCEPT, [:service_name, :string]

    register Authentication::Constants::USERAUTH_BANNER, [:message, :string], [:language, :string]
    register Authentication::Constants::USERAUTH_FAILURE, [:authentications, :string], [:partial_success, :bool]

    register Connection::Constants::GLOBAL_REQUEST, [:request_type, :string], [:want_reply, :bool], [:request_data, :buffer]
    register Connection::Constants::CHANNEL_OPEN, [:channel_type, :string], [:remote_id, :long], [:window_size, :long], [:packet_size, :long]
    register Connection::Constants::CHANNEL_OPEN_CONFIRMATION, [:local_id, :long], [:remote_id, :long], [:window_size, :long], [:packet_size, :long]
    register Connection::Constants::CHANNEL_WINDOW_ADJUST, [:local_id, :long], [:extra_bytes, :long]
    register Connection::Constants::CHANNEL_DATA, [:local_id, :long], [:data, :string]
    register Connection::Constants::CHANNEL_EXTENDED_DATA, [:local_id, :long], [:data_type, :long], [:data, :string]
    register Connection::Constants::CHANNEL_EOF, [:local_id, :long]
    register Connection::Constants::CHANNEL_CLOSE, [:local_id, :long]
    register Connection::Constants::CHANNEL_REQUEST, [:local_id, :long], [:request, :string], [:want_reply, :bool], [:request_data, :buffer]
    register Connection::Constants::CHANNEL_SUCCESS, [:local_id, :long]
    register Connection::Constants::CHANNEL_FAILURE, [:local_id, :long]

    # The (integer) type of this packet.
    attr_reader :type

    # Create a new packet from the given payload. This will automatically
    # parse the packet if it is one that has been previously registered with
    # Packet.register.
    def initialize(payload)
      @instantiated = false
      @named_elements = {}
      super
      @type = read_byte
      instantiate!
    end

    # Access one of the auto-parsed fields by name. Raises an error if no
    # element by the given name exists.
    def [](name)
      name = name.to_sym
      raise ArgumentError, "no such element #{name}" unless @named_elements.key?(name)
      @named_elements[name]
    end

    private

      # Parse the packet's contents and assign the named elements, as described
      # by the registered format for the packet.
      def instantiate!
        (@@types[type] || []).each do |name, datatype|
          @named_elements[name.to_sym] = if datatype == :buffer
            remainder_as_buffer
          else
            send("read_#{datatype}")
          end
        end
      end
  end
end; end