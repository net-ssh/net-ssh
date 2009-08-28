require 'thread'

class String
  if RUBY_VERSION < "1.9"
    def getbyte(index)
      self[index]
    end
  end
end

module Net; module SSH
  
  # This class contains miscellaneous patches and workarounds
  # for different ruby implementations.
  class Compat
    
    # A workaround for an IO#select threading bug in MRI 1.8.
    # See: http://net-ssh.lighthouseapp.com/projects/36253/tickets/1-ioselect-threading-bug-in-ruby-18
    # Also: http://redmine.ruby-lang.org/issues/show/1993
    if RUBY_VERSION >= '1.9' || RUBY_PLATFORM == 'java'
      def self.io_select(*params)
        IO.select(*params)
      end
    else
      SELECT_MUTEX = Mutex.new
      def self.io_select(*params)
        SELECT_MUTEX.synchronize do
          IO.select(*params)
        end
      end
    end
    
  end
  
end; end
