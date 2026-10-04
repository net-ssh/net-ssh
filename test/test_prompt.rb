require_relative 'common'
require 'net/ssh/prompt'

class TestPrompt < NetSSHTest
  class FakeTTY < StringIO
    attr_reader :noecho_used

    def noecho
      @noecho_used = true
      yield self
    end
  end

  def test_ask_with_echo_should_read_input_visibly
    answer, stdin, stdout = ask("user\n", "Login: ", true)

    assert_equal "user", answer
    refute stdin.noecho_used
    assert_equal "Login: ", stdout.string
  end

  def test_ask_without_echo_should_hide_input_and_end_the_line
    answer, stdin, stdout = ask("secret\n", "Password: ", false)

    assert_equal "secret", answer
    assert stdin.noecho_used
    assert_equal "Password: \n", stdout.string
  end

  private

  def ask(input, prompt, echo)
    stdin = FakeTTY.new(input)
    stdout = StringIO.new
    $stdin = stdin
    $stdout = stdout
    answer = Net::SSH::Prompt.default.start(type: 'password').ask(prompt, echo)
    [answer, stdin, stdout]
  ensure
    $stdin = STDIN
    $stdout = STDOUT
  end
end
