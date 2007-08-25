require 'net/ssh/connection/constants'
require 'net/ssh/transport/constants'

module Net; module SSH; module Test

  class Packet
    include Net::SSH::Transport::Constants
    include Net::SSH::Connection::Constants

    def initialize(type, *args, &init)
      @type = self.class.const_get(type.to_s.upcase)
      @data = args
      @init = init
    end

    def remote?
      false
    end

    def local?
      false
    end

    def instantiate!
      @data.map! { |i| i.respond_to?(:call) ? i.call : i }
    end

    def types
      @types ||= case @type
        when KEXINIT then 
          [:long, :long, :long, :long,
           :string, :string, :string, :string, :string, :string, :string, :string, :string, :string,
           :bool]
        when NEWKEYS then []
        when CHANNEL_OPEN then [:string, :long, :long, :long]
        when CHANNEL_OPEN_CONFIRMATION then [:long, :long, :long, :long]
        when CHANNEL_DATA then [:long, :string]
        when CHANNEL_EOF, CHANNEL_CLOSE, CHANNEL_SUCCESS, CHANNEL_FAILURE then [:long]
        when CHANNEL_REQUEST
          parts = [:long, :string, :bool]
          case @data[1]
          when "exec" then parts << :string
          when "exit-status" then parts << :long
          else raise "don't know what to do about #{@data[1]} channel request"
          end
        else raise "don't know how to parse packet type #{@type}"
        end
    end
  end

end; end; end