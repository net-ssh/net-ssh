require 'thread'
require 'io/wait'

module Net; module SSH
  
  # This class contains miscellaneous patches and workarounds
  # for different ruby implementations.
  class Compat
    def self.io_select(*params)
      IO.select(*params)
    end
  end
  
end; end
