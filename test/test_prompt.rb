require_relative 'common'
require 'net/ssh/prompt'
require 'tmpdir'

class TestPrompt < NetSSHTest
  class FakeTTY < StringIO
    attr_reader :noecho_used

    def tty?
      true
    end

    def noecho
      @noecho_used = true
      yield self
    end
  end

  def test_ask_with_echo_should_read_input_visibly
    answer, stdin, stdout = ask(FakeTTY.new("user\n"), "Login: ", true)

    assert_equal "user", answer
    refute stdin.noecho_used
    assert_equal "Login: ", stdout.string
  end

  def test_ask_without_echo_should_hide_input_and_end_the_line
    answer, stdin, stdout = ask(FakeTTY.new("secret\n"), "Password: ", false)

    assert_equal "secret", answer
    assert stdin.noecho_used
    assert_equal "Password: \n", stdout.string
  end

  def test_ask_without_echo_should_read_a_pipe_without_noecho
    answer, _stdin, stdout = ask(StringIO.new("secret\n"), "Password: ", false)

    assert_equal "secret", answer
    assert_equal "Password: \n", stdout.string
  end

  def test_can_ask_only_with_a_tty
    $stdin = FakeTTY.new
    assert Net::SSH::Prompt.can_ask?
    $stdin = StringIO.new
    refute Net::SSH::Prompt.can_ask?
  ensure
    $stdin = STDIN
  end

  def test_askpass_is_used_without_a_tty_when_a_display_is_set
    with_env('SSH_ASKPASS' => '/bin/askpass', 'DISPLAY' => ':0') do
      $stdin = StringIO.new
      assert_equal '/bin/askpass', Net::SSH::Prompt.askpass
      assert Net::SSH::Prompt.can_ask?
      $stdin = FakeTTY.new
      assert_nil Net::SSH::Prompt.askpass
    end
    with_env('SSH_ASKPASS' => '/bin/askpass', 'WAYLAND_DISPLAY' => 'wayland-0') do
      $stdin = StringIO.new
      assert_equal '/bin/askpass', Net::SSH::Prompt.askpass
    end
  ensure
    $stdin = STDIN
  end

  def test_askpass_needs_a_display_and_a_program
    $stdin = StringIO.new
    with_env('SSH_ASKPASS' => '/bin/askpass') do
      assert_nil Net::SSH::Prompt.askpass
      refute Net::SSH::Prompt.can_ask?
    end
    with_env('SSH_ASKPASS' => '', 'DISPLAY' => ':0', 'SSH_ASKPASS_REQUIRE' => 'force') do
      assert_nil Net::SSH::Prompt.askpass
    end
  ensure
    $stdin = STDIN
  end

  def test_askpass_require
    $stdin = FakeTTY.new
    with_env('SSH_ASKPASS' => '/bin/askpass', 'SSH_ASKPASS_REQUIRE' => 'force') do
      assert_equal '/bin/askpass', Net::SSH::Prompt.askpass
    end
    with_env('SSH_ASKPASS' => '/bin/askpass', 'SSH_ASKPASS_REQUIRE' => 'prefer') do
      assert_nil Net::SSH::Prompt.askpass
    end
    with_env('SSH_ASKPASS' => '/bin/askpass', 'SSH_ASKPASS_REQUIRE' => 'prefer', 'DISPLAY' => ':0') do
      assert_equal '/bin/askpass', Net::SSH::Prompt.askpass
    end
    $stdin = StringIO.new
    with_env('SSH_ASKPASS' => '/bin/askpass', 'SSH_ASKPASS_REQUIRE' => 'never', 'DISPLAY' => ':0') do
      assert_nil Net::SSH::Prompt.askpass
    end
  ensure
    $stdin = STDIN
  end

  def test_ask_should_run_askpass_with_the_prompt
    with_askpass_script('printf "%s|" "$1" > "$0.args"; echo secret') do |script|
      answer, _stdin, stdout = ask(StringIO.new, "Password: ", false)

      assert_equal "secret", answer
      assert_equal "Password: |", File.read("#{script}.args")
      assert_equal "", stdout.string
    end
  end

  def test_ask_should_answer_empty_when_askpass_fails
    with_askpass_script('echo partial; exit 1') do
      answer, = ask(StringIO.new, "Password: ", false)

      assert_equal "", answer
    end
  end

  def test_keyboard_interactive_should_pass_name_and_instruction_to_askpass
    with_askpass_script('printf "%s|" "$1" >> "$0.args"; echo answer') do |script|
      stdout = StringIO.new
      $stdin = StringIO.new
      $stdout = stdout
      prompter = Net::SSH::Prompt.default.start(type: 'keyboard-interactive', name: 'Name', instruction: 'Instruction')
      assert_equal "answer", prompter.ask("Code: ", false)
      assert_equal "answer", prompter.ask("Again: ", false)

      assert_equal "Name\nInstruction\nCode: |Again: |", File.read("#{script}.args")
      assert_equal "", stdout.string
    ensure
      $stdin = STDIN
      $stdout = STDOUT
    end
  end

  private

  def with_env(vars)
    keys = %w[SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY WAYLAND_DISPLAY]
    saved = ENV.to_h.slice(*keys)
    keys.each { |key| ENV.delete(key) }
    ENV.update(vars)
    yield
  ensure
    keys.each { |key| ENV.delete(key) }
    ENV.update(saved)
  end

  def with_askpass_script(body)
    skip "askpass test script needs a POSIX shell" if Gem.win_platform?
    Dir.mktmpdir do |dir|
      script = File.join(dir, 'askpass')
      File.write(script, "#!/bin/sh\n#{body}\n")
      File.chmod(0o700, script)
      with_env('SSH_ASKPASS' => script, 'SSH_ASKPASS_REQUIRE' => 'force') { yield script }
    end
  end

  def ask(stdin, prompt, echo)
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
