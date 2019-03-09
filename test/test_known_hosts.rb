require 'common'

class TestKnownHosts < NetSSHTest
  def perform_test(source)
    kh = Net::SSH::KnownHosts.new(source)
    keys = kh.keys_for("github.com")
    assert_equal(1, keys.count)
    assert_equal("ssh-rsa", keys[0].ssh_type)
  end

  def test_key_for_when_all_hosts_are_recognized
    perform_test(path("known_hosts/github"))
  end

  def test_key_for_when_an_host_hash_is_recognized
    perform_test(path("known_hosts/github_hash"))
  end

  def test_missing_then_add
    Tempfile.open('github') do |f|
      f.write(File.read(path("known_hosts/github")))
      kh = Net::SSH::KnownHosts.new(f.path)
      keys = kh.keys_for("github2.com")
      assert_equal(0, keys.count)
      assert_equal([], keys.to_a)

      kh.add('github2.com',rsa_key)
      keys2 = kh.keys_for("github2.com")
      assert_equal([rsa_key.to_blob], keys2.to_a.map(&:to_blob))
    end
  end

  def test_search_for
    options = { user_known_hosts_file: path("known_hosts/github") }
    keys = Net::SSH::KnownHosts.search_for('github.com',options)
    assert_equal(["ssh-rsa"], keys.map(&:ssh_type))
  end

  def test_search_for_with_hostname_and_right_ip_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,35.231.145.151',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_and_right_ip_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,35.231.145.151',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_and_wrong_ip_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,192.0.2.1',options)
    assert_equal(0, keys.count)
  end

  def test_search_for_with_hostname_and_wrong_ip_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,192.0.2.2',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_only_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_only_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_ip_only_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('35.231.145.151',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_ip_only_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('35.231.145.151',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_matching_pattern
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('subdomain.gitfoo.com',options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_not_matching_pattern_1
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('gitfoo.com',options)
    assert_equal(0, keys.count)
  end

  def test_search_for_with_hostname_not_matching_pattern_2
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('subdomain.gitmisc.com',options)
    assert_equal(0, keys.count)
  end

  def test_search_for_with_hostname_not_matching_pattern_3
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('subsubdomain.subdomain.gitfoo.com',options)
    assert_equal(0, keys.count)
  end

  def test_search_for_then_add
    Tempfile.open('github') do |f|
      f.write(File.read(path("known_hosts/github")))
      options = { user_known_hosts_file: f.path }
      keys = Net::SSH::KnownHosts.search_for('github2.com',options)
      assert_equal(0, keys.count)

      keys.add_host_key(rsa_key)

      assert_equal([rsa_key.to_blob], keys.map(&:to_blob))
      keys = Net::SSH::KnownHosts.search_for('github2.com',options)
      assert_equal([rsa_key.to_blob], keys.map(&:to_blob))
    end
  end

  def path(relative_path)
    File.join(File.dirname(__FILE__), relative_path)
  end

  def rsa_key
    key = OpenSSL::PKey::RSA.new
    if key.respond_to?(:set_key)
      key.set_key(0x7766554433221100, 0xffeeddccbbaa9988, nil)
    else
      key.e = 0xffeeddccbbaa9988
      key.n = 0x7766554433221100
    end
    key
  end
end
