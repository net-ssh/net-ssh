module Net; module SSH
  class Version
    MAJOR = 1
    MINOR = 99
    TINY  = 0

    def self.current
      @current ||= new(MAJOR, MINOR, TINY)
    end

    def self.[](major, minor, tiny)
      new(major, minor, tiny)
    end

    attr_reader :major, :minor, :tiny

    def initialize(major, minor, tiny)
      @major, @minor, @tiny = major, minor, tiny
    end

    def <=>(version)
      to_i <=> version.to_i
    end

    def to_s
      @to_s ||= [@major, @minor, @tiny].join(".")
    end

    def to_i
      @to_i ||= @major * 1_000_000 + @minor * 1_000 + @tiny
    end

    STRING = current.to_s
  end
end; end