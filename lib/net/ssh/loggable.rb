module Net; module SSH

  # A simple module to make logging easier to deal with. It assumes that the
  # logger instance (if not nil) quacks like a Logger object (in Ruby's
  # standard library).
  #
  # The Logger output levels have been reinterpreted by Net::SSH as follows:
  #
  # * Logger::DEBUG: trace messages
  # * Logger::INFO: debug messages
  # * Logger::WARN: information messages
  # * Logger::ERROR: standard log messages
  # * Logger::FATAL: error messages
  module Loggable
    # The logger instance that will be used to log messages. If nil, nothing
    # will be logged.
    attr_accessor :logger

    # Displays the result of yielding if the log level is sufficient.
    def trace
      logger.add(0, nil, facility) { yield } if logger
    end

    # Displays the result of yielding if the log level is sufficient.
    def debug
      logger.add(1, nil, facility) { yield } if logger
    end

    # Displays the result of yielding if the log level is sufficient.
    def info
      logger.add(2, nil, facility) { yield } if logger
    end

    # Displays the result of yielding if the log level is sufficient.
    def log
      logger.add(3, nil, facility) { yield } if logger
    end

    # Displays the result of yielding if the log level is sufficient.
    def error
      logger.add(4, nil, facility) { yield } if logger
    end

    private

      # Sets the "facility" value, used for reporting where a log message
      # originates. It defaults to the name of class.
      def facility
        @facility ||= self.class.name.gsub(/::/, ".").gsub(/([a-z])([A-Z])/, "\\1_\\2").downcase
      end
  end
end; end