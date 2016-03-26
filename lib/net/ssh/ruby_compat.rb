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
end

module Net; module SSH
  
  # This class contains miscellaneous patches and workarounds
  # for different ruby implementations.
  class Compat
    def self.io_select(*params)
      IO.select(*params)
    end
  end
  
end; end
