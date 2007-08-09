require 'net/ssh/verifiers/strict'

module Net; module SSH; module Verifiers

  class Lenient < Strict
    def verify(arguments)
      return true if tunnelled?(arguments)
      super
    end

    private

      # A connection is potentially being tunnelled if the port is not 22,
      # and the ip refers to the localhost.
      def tunnelled?(args)
        return false if args[:session].port == Net::SSH::Transport::Session::DEFAULT_PORT
        
        ip = args[:session].peer[:ip]
        return ip == "127.0.0.1" || ip == "::1"
      end
  end

end; end; end