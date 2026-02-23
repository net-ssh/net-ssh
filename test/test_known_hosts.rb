require_relative './common'

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

  def test_parsing_known_hosts_empty_lines_and_comments
    perform_test(path("known_hosts/known_hosts_ignore"))
  end

  def test_missing_then_add
    Tempfile.open('github') do |f|
      f.write(File.read(path("known_hosts/github")))
      kh = Net::SSH::KnownHosts.new(f.path)
      keys = kh.keys_for("github2.com")
      assert_equal(0, keys.count)
      assert_equal([], keys.to_a)

      kh.add('github2.com', rsa_key)
      keys2 = kh.keys_for("github2.com")
      assert_equal([rsa_key.to_blob], keys2.to_a.map(&:to_blob))
    end
  end

  def test_search_for
    options = { user_known_hosts_file: path("known_hosts/github"), global_known_hosts_file: [] }
    keys = Net::SSH::KnownHosts.search_for('github.com', options)
    assert_equal(["ssh-rsa"], keys.map(&:ssh_type))
  end

  def test_search_for_with_hostname_and_right_ip_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,35.231.145.151', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_and_right_ip_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,35.231.145.151', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_and_wrong_ip_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,192.0.2.1', options)
    assert_equal(0, keys.count)
  end

  def test_search_for_with_hostname_and_wrong_ip_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com,192.0.2.2', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_only_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_only_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('gitlab.com', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_ip_only_with_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: true }
    keys = Net::SSH::KnownHosts.search_for('35.231.145.151', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_ip_only_without_check_host_ip
    options = { user_known_hosts_file: path("known_hosts/gitlab"), check_host_ip: false }
    keys = Net::SSH::KnownHosts.search_for('35.231.145.151', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_matching_pattern
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('subdomain.gitfoo.com', options)
    assert_equal(1, keys.count)
  end

  def test_search_for_with_hostname_not_matching_pattern_1
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('gitfoo.com', options)
    assert_equal(0, keys.count)
  end

  def test_search_for_with_hostname_not_matching_pattern_2
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('subdomain.gitmisc.com', options)
    assert_equal(0, keys.count)
  end

  def test_search_for_with_hostname_not_matching_pattern_3
    options = { user_known_hosts_file: path("known_hosts/misc") }
    keys = Net::SSH::KnownHosts.search_for('subsubdomain.subdomain.gitfoo.com', options)
    assert_equal(1, keys.count)
  end

  def test_asterisk_matches_multiple_dots
    with_config_file(lines: ["*.git???.com #{sample_key}"]) do |path|
      options = { user_known_hosts_file: path }
      keys = Net::SSH::KnownHosts.search_for('subsubdomain.subdomain.gitfoo.com', options)
      assert_equal(1, keys.count)

      keys = Net::SSH::KnownHosts.search_for('subsubdomain.subdomain.gitfoo2.com', options)
      assert_equal(0, keys.count)
    end
  end

  def test_asterisk_matches_everything
    with_config_file(lines: ["* #{sample_key}"]) do |path|
      options = { user_known_hosts_file: path }
      keys = Net::SSH::KnownHosts.search_for('subsubdomain.subdomain.gitfoo.com', options)
      assert_equal(1, keys.count)

      keys = Net::SSH::KnownHosts.search_for('subsubdomain.subdomain.gitfoo2.com', options)
      assert_equal(1, keys.count)
    end
  end

  def test_search_for_then_add
    Tempfile.open('github') do |f|
      f.write(File.read(path("known_hosts/github")))
      options = { user_known_hosts_file: f.path }
      keys = Net::SSH::KnownHosts.search_for('github2.com', options)
      assert_equal(0, keys.count)

      keys.add_host_key(rsa_key)

      assert_equal([rsa_key.to_blob], keys.map(&:to_blob))
      keys = Net::SSH::KnownHosts.search_for('github2.com', options)
      assert_equal([rsa_key.to_blob], keys.map(&:to_blob))
    end
  end

  def path(relative_path)
    File.join(File.dirname(__FILE__), relative_path)
  end

  def sample_key
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ=="
  end

  def with_config_file(lines: [], &block)
    Tempfile.open('known_hosts') do |f|
      f.write(lines.join("\n"))
      f.close
      yield(f.path)
    end
  end

  def rsa_key
    n = 0x7766554433221100
    e = 0xffeeddccbbaa9988
    asn1 = OpenSSL::ASN1::Sequence(
      [
        OpenSSL::ASN1::Integer(n),
        OpenSSL::ASN1::Integer(e)
      ]
    )
    OpenSSL::PKey::RSA.new(asn1.to_der)
  end
end

class TestCertAuthority < NetSSHTest
  def make_cert(valid_principals: [], valid_after: nil, valid_before: nil)
    OpenStruct.new(
      valid_principals: valid_principals,
      valid_after: valid_after,
      valid_before: valid_before
    )
  end

  def ca
    Net::SSH::HostKeyEntries::CertAuthority.new(OpenStruct.new(to_blob: "ca-blob"))
  end

  # matches_principal?

  def test_matches_principal_when_hostname_is_listed
    cert = make_cert(valid_principals: ["server.example.com", "other.example.com"])
    assert ca.matches_principal?(cert, "server.example.com")
  end

  def test_matches_principal_rejects_unlisted_hostname
    cert = make_cert(valid_principals: ["server.example.com"])
    refute ca.matches_principal?(cert, "other.example.com")
  end

  def test_matches_principal_allows_all_when_principals_empty
    cert = make_cert(valid_principals: [])
    assert ca.matches_principal?(cert, "any.host.example.com")
  end

  # matches_validity?

  def test_matches_validity_for_cert_within_window
    cert = make_cert(valid_after: Time.now - 3600, valid_before: Time.now + 3600)
    assert ca.matches_validity?(cert)
  end

  def test_matches_validity_rejects_expired_cert
    cert = make_cert(valid_after: Time.now - 7200, valid_before: Time.now - 3600)
    refute ca.matches_validity?(cert)
  end

  def test_matches_validity_rejects_not_yet_valid_cert
    cert = make_cert(valid_after: Time.now + 3600, valid_before: Time.now + 7200)
    refute ca.matches_validity?(cert)
  end

  def test_matches_validity_when_valid_after_is_nil
    cert = make_cert(valid_after: nil, valid_before: Time.now + 3600)
    assert ca.matches_validity?(cert)
  end

  def test_matches_validity_when_valid_before_is_nil
    cert = make_cert(valid_after: Time.now - 3600, valid_before: nil)
    assert ca.matches_validity?(cert)
  end

  def test_matches_validity_when_both_bounds_are_nil
    cert = make_cert(valid_after: nil, valid_before: nil)
    assert ca.matches_validity?(cert)
  end
end

class TestHostKeysHostname < NetSSHTest
  def make_host_keys(host)
    Net::SSH::HostKeys.new([], host, nil)
  end

  def test_hostname_plain
    assert_equal "server.example.com", make_host_keys("server.example.com").hostname
  end

  def test_hostname_strips_ip
    assert_equal "server.example.com", make_host_keys("server.example.com,1.2.3.4").hostname
  end

  def test_hostname_strips_port
    assert_equal "server.example.com", make_host_keys("[server.example.com]:2222").hostname
  end

  def test_hostname_strips_port_and_ip
    assert_equal "server.example.com",
                 make_host_keys("[server.example.com]:2222,[1.2.3.4]:2222").hostname
  end
end
