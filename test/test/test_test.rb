require_relative '../common'
require 'net/ssh/test'

class TestNetSSHTest < NetSSHTest
  include Net::SSH::Test

  def test_example
    story do |session|
      channel = session.opens_channel
      channel.sends_exec "ls"
      channel.gets_data "result of ls"
      channel.gets_close
      channel.sends_close
    end

    assert_scripted do
      result = nil

      connection.open_channel do |ch|
        ch.exec("ls") do |_success|
          ch.on_data { |_c, data| result = data }
          ch.on_close { |c| c.close }
        end
      end

      connection.loop
      assert_equal "result of ls", result
    end
  end

  def test_pty
    story do |session|
      channel = session.opens_channel
      channel.sends_request_pty
      session.sends_channel_request(channel, "shell", false, nil, true)
      channel.sends_exec "ls"
      channel.gets_data "result of ls"
      channel.gets_close
      channel.sends_close
    end

    assert_scripted do
      result = nil
      connection.open_channel do |ch|
        ch.request_pty
        ch.send_channel_request("shell")
        ch.exec("ls") do |_success|
          ch.on_data { |_c, data| result = data }
          ch.on_close { |c| c.close }
        end
      end

      connection.loop
      assert_equal "result of ls", result
    end
  end

  def test_custom
    Packet.register_channel_request("custom", %i[string string long])
    story do |session|
      channel = session.opens_channel
      session.sends_channel_request(channel, "custom", false, ["hello", "hello", 42], true)
      channel.gets_close
      channel.sends_close
    end

    assert_scripted do
      connection.open_channel do |ch|
        ch.send_channel_request("custom", :string, "hello", :string, "hello", :long, 42)
        ch.on_close { |c| c.close }
      end

      connection.loop
    end
  end
end