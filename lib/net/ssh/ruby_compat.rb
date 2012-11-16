require 'thread'

class String
  if RUBY_VERSION < "1.9"
    def getbyte(index)
      self[index]
    end
    def setbyte(index, c)
      self[index] = c
    end
  end
  if RUBY_VERSION < "1.8.7"
    def bytesize
      self.size
    end
  end
end

module Net; module SSH
  
  # This class contains miscellaneous patches and workarounds
  # for different ruby implementations.
  class Compat
    
    # A workaround for an IO#select threading bug in certain versions of MRI 1.8.
    # See: http://net-ssh.lighthouseapp.com/projects/36253/tickets/1-ioselect-threading-bug-in-ruby-18
    # The root issue is documented here: http://redmine.ruby-lang.org/issues/show/1993
    if RUBY_VERSION >= '1.9' || RUBY_PLATFORM == 'java'
      
      # problem: Pageant sockets aren't real sockets/don't inherit from IO, so we can't call IO.select on them
      # solution: when a Pageant socket is found in the readers/writers array, slice it out then merge it back in before returning (just assume it's always ready)
      # unfortunately this fix will also need to be ported to any other library that reaches in to Net::SSH and select's its sockets (like Capistrano)
      # this is slightly more verbose than necessary, but it's useful for debugging
      def self.io_select(*params)
        read_array = params[0]
        write_array = params[1]
        error_array = params[2]
        timeout = params[3]

        read_sockets = read_array.nil? ? [] : read_array.reject {|s| s.class.name =~ /Pageant/ }
        read_pageant = read_array.nil? ? [] : read_array.select {|s| s.class.name =~ /Pageant/ }

        write_sockets = write_array.nil? ? [] : write_array.reject {|s| s.class.name =~ /Pageant/ }
        write_pageant = write_array.nil? ? [] : write_array.select {|s| s.class.name =~ /Pageant/ }

        result = IO.select(read_sockets, write_sockets, error_array, timeout)

        if result.nil?
          return nil
        else
          ready_read_sockets = result[0]
          ready_write_sockets = result[1]
          ready_error_array_only_sockets = result[2]

          return [ready_read_sockets | read_pageant, ready_write_sockets | write_pageant, ready_error_array_only_sockets]
        end
      end
    else
      SELECT_MUTEX = Mutex.new
      def self.io_select(*params)
        # It should be safe to wrap calls in a mutex when the timeout is 0
        # (that is, the call is not supposed to block).
        # We leave blocking calls unprotected to avoid causing deadlocks.
        # This should still catch the main case for Capistrano users.
        if params[3] == 0
          SELECT_MUTEX.synchronize do
            IO.select(*params)
          end
        else
          IO.select(*params)
        end
      end
    end
    
  end
  
end; end
