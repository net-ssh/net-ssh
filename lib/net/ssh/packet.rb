require 'net/ssh/buffer'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'

module Net; module SSH
  class Packet < Buffer
    @@types = {}
    def self.register(type, *pairs)
      @@types[type] = pairs
    end

    register Transport::Constants::SERVICE_ACCEPT, [:service_name, :string]

    register Authentication::Constants::USERAUTH_BANNER, [:message, :string], [:language, :string]
    register Authentication::Constants::USERAUTH_FAILURE, [:authentications, :string], [:partial_success, :bool]

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
        @named_elements[name.to_sym] = send("read_#{datatype}")
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