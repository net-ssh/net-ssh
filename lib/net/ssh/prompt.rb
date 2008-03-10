module Net; module SSH

  # A basic prompt module that can be mixed into other objects. If HighLine is
  # installed, it will be used to display prompts and read input from the
  # user. Otherwise, the termios library will be used. If neither HighLine
  # nor termios is installed, a simple prompt that echos text in the clear
  # will be used.

  module PromptMethods
    module Highline
      def prompt(prompt, echo=true)
        @highline ||= ::HighLine.new
        @highline.ask(prompt + " ") { |q| q.echo = echo }
      end
    end

    module Termios
      def set_echo(enable)
        term = ::Termios.getattr($stdin)

        if enable
          term.c_lflag |= (::Termios::ECHO | ::Termios::ICANON)
        else
          term.c_lflag &= ~::Termios::ECHO
        end

        ::Termios.setattr($stdin, ::Termios::TCSANOW, term)
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
    end

    module Clear
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

  Prompt = begin
      require 'highline'
      HighLine.track_eof = false
      PromptMethods::Highline
    rescue LoadError
      begin
        require 'termios'
        PromptMethods::Termios
      rescue LoadError
        PromptMethods::Clear
      end
    end

end; end