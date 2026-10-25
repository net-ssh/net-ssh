require 'io/console'

module Net
  module SSH
    # Default prompt implementation, called for asking password from user.
    # It will never be instantiated directly, but will instead be created for
    # you automatically.
    #
    # A custom prompt objects can implement caching, or different UI. The prompt
    # object should implemnted a start method, which should return something implementing
    # ask and success. Net::SSH uses it like:
    #
    #   prompter = options[:password_prompt].start({type:'password'})
    #   while !ok && max_retries < 3
    #     user = prompter.ask("user: ", true)
    #     password = prompter.ask("password: ", false)
    #     ok = send(user, password)
    #     prompter.sucess if ok
    #   end
    #
    class Prompt
      # factory
      def self.default(options = {})
        @default ||= new(options)
      end

      def initialize(options = {}); end

      # Whether the default prompt has a terminal or an askpass program to ask with.
      def self.can_ask?
        $stdin.tty? || !askpass.nil?
      end

      # The SSH_ASKPASS program to ask with instead of the terminal, chosen with
      # the SSH_ASKPASS_REQUIRE and DISPLAY rules described in ssh(1).
      def self.askpass
        program = ENV['SSH_ASKPASS'].to_s
        return nil if program.empty?

        display = !ENV['DISPLAY'].to_s.empty? || !ENV['WAYLAND_DISPLAY'].to_s.empty?
        case ENV['SSH_ASKPASS_REQUIRE'].to_s.downcase
        when 'force' then program
        when 'never' then nil
        when 'prefer' then (program if display)
        else (program if display && !$stdin.tty?)
        end
      end

      # default prompt object implementation. More sophisticated implemenetations
      # might implement caching.
      class Prompter
        def initialize(info)
          @askpass = Prompt.askpass
          @header = []
          if info[:type] == 'keyboard-interactive'
            @header << info[:name] unless info[:name].empty?
            @header << info[:instruction] unless info[:instruction].empty?
          end
          $stdout.puts(@header) unless @askpass || @header.empty?
        end

        # ask input from user, a prompter might ask for multiple inputs
        # (like user and password) in a single session.
        def ask(prompt, echo = true)
          return ask_askpass(prompt) if @askpass

          $stdout.print(prompt)
          $stdout.flush
          hide = !echo && $stdin.tty?
          ret = hide ? $stdin.noecho(&:gets) : $stdin.gets
          $stdout.print("\n") unless echo
          ret.chomp
        end

        # success method will be called when the password was accepted
        # It's a good time to save password asked to a cache.
        def success; end

        private

        # Like OpenSSH, a cancelled or failed askpass answers with an empty string.
        def ask_askpass(prompt)
          text = (@header + [prompt]).join("\n")
          @header = []
          answer = IO.popen([@askpass, text], &:read)
          Process.last_status.success? ? answer.chomp : ""
        end
      end

      # start password session. Multiple questions might be asked multiple times
      # on the returned object. Info hash tries to uniquely identify the password
      # session, so caching implementations can save passwords properly.
      def start(info)
        Prompter.new(info)
      end
    end
  end
end
