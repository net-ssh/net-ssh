module Net; module SSH
  module Loggable
    attr_accessor :logger

    def trace
      logger.add(0, nil, facility) { yield } if logger
    end

    def debug
      logger.add(1, nil, facility) { yield } if logger
    end

    def info
      logger.add(2, nil, facility) { yield } if logger
    end

    def log
      logger.add(3, nil, facility) { yield } if logger
    end

    def error
      logger.add(4, nil, facility) { yield } if logger
    end

    private

      def facility
        @facility ||= self.class.name.gsub(/::/, ".").gsub(/([a-z])([A-Z])/, "\\1_\\2").downcase
      end
  end
end; end