require 'common'

class TestKnownHosts < Test::Unit::TestCase

  def perform_test(hostfile)
    source = File.join(File.dirname(__FILE__), hostfile)
    kh = Net::SSH::KnownHosts.new(source)
    keys = kh.keys_for("github.com")
    assert_equal(1, keys.count)
    assert_equal("ssh-rsa", keys[0].ssh_type)
  end

  def test_key_for_when_all_hosts_are_recognized
    perform_test("known_hosts/github")
  end

  def test_key_for_when_an_host_hash_is_recognized
    perform_test("known_hosts/github_hash")
  end

end
