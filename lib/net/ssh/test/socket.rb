require 'socket'
require 'stringio'
require 'net/ssh/test/extensions'
require 'net/ssh/test/script'

module Net; module SSH; module Test

  class Socket < StringIO
    attr_reader :host, :port, :script

    def initialize
      extend(Net::SSH::Transport::PacketStream)
      super "SSH-2.0-Test\r\n"

      @script = Script.new

      script.gets(:kexinit, 1, 2, 3, 4, "test", "ssh-rsa", "none", "none", "none", "none", "none", "none", "", "", false)
      script.sends(:kexinit)
      script.sends(:newkeys)
      script.gets(:newkeys)
    end

    def write(data)
      # black hole, because we don't actually care about what gets written
    end

    def open(host, port)
      @host, @port = host, port
      self
    end

    def getpeername
      ::Socket.sockaddr_in(port, host)
    end

    def recv(n)
      read(n) || ""
    end
  end

end; end; end
