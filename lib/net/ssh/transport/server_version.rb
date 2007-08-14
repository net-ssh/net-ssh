require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/version'

module Net; module SSH; module Transport
  class ServerVersion
    include Loggable

    PROTO_VERSION = "SSH-2.0-Ruby/Net::SSH_#{Net::SSH::Version.current} #{RUBY_PLATFORM}"

    attr_reader :header
    attr_reader :version

    def initialize(socket, logger)
      @header = ""
      @version = nil
      @logger = logger
      negotiate!(socket)
    end

    private

      def negotiate!(socket)
        loop do
          @version = socket.readline
          break if @version.nil? || @version.match(/^SSH-/)
          @header << @version
        end

        trace { "remote is #{@version.strip}" }

        unless @version.match(/^SSH-(1\.99|2\.0)-/)
          raise Net::SSH::Exception, "incompatible SSH version `#{@version}'"
        end

        @version.strip!

        trace { "local is #{PROTO_VERSION}" }
        socket.write "#{PROTO_VERSION}\r\n"
      end
  end
end; end; end