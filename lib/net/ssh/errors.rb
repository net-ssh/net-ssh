module Net; module SSH
  class Exception < ::RuntimeError; end

  class AuthenticationFailed < Exception; end

  class Disconnect < Exception; end

  class ChannelOpenFailed < Exception
    attr_reader :code, :reason

    def initialize(code, reason)
      @code, @reason = code, reason
      super "#{reason} (#{code})"
    end
  end

  # Raised when the cached key for a particular host does not match the
  # key given by the host, which can be indicative of a man-in-the-middle
  # attack. When rescuing this exception, you can inspect the key fingerprint
  # and, if you want to proceed anyway, simply call the remember_host!
  # method on the exception, and then retry.
  class HostKeyMismatch < Exception
    attr_writer :callback, :data

    def [](key)
      @data[key]
    end

    def fingerprint
      @data[:fingerprint]
    end

    def host
      @data[:peer][:host]
    end

    def port
      @data[:peer][:port]
    end

    def ip
      @data[:peer][:ip]
    end

    def key
      @data[:key]
    end

    def remember_host!
      @callback.call
    end
  end
end; end