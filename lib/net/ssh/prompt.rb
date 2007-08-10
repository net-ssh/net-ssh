module Net; module SSH

  PROMPTS = {}

  begin
    require 'highline'
    HighLine.track_eof = false
    PROMPTS[:highline] = true
  rescue LoadError
    begin
      require 'termios'
      PROMPTS[:termios] = true
    rescue LoadError
      # we'll just have to use plain-text
    end
  end

  module Prompt
    if PROMPTS[:highline]

      def prompt(prompt, echo=true)
        @highline ||= HighLine.new
        @highline.ask(prompt + " ") { |q| q.echo = echo }
      end

    elsif PROMPTS[:termios]

      def set_echo(enable)
        term = Termios.getattr($stdin)

        if enable
          term.c_lflag |= (Termios::ECHO | Termios::ICANON)
        else
          term.c_lflag &= ~Termios::ECHO
        end

        Termios.setattr($stdin, Termios::TCSANOW, term)
      end
      private :set_echo

      def prompt(prompt, echo=true)
        $stdout.print(prompt)
        $stdout.flush

        set_echo(false) unless echo
        $stdin.gets.chomp
      ensure
        if !echo
          set_echo(true)
          $stdout.puts
        end
      end

    else

      def prompt(prompt, echo=true)
        @seen_warning ||= false
        if !echo && !@seen_warning
          $stderr.puts "Text will be echoed in the clear. Please install the HighLine or Termios libraries to suppress echoed text."
          @seen_warning = true
        end

        $stdout.print(prompt)
        $stdout.flush
        $stdin.gets.chomp
      end

    end
  end

end; end