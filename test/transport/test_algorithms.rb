require_relative '../common'
require 'logger'
require 'net/ssh/transport/algorithms'
require 'net/ssh/config'

module Transport
  class TestAlgorithms < NetSSHTest
    include Net::SSH::Transport::Constants

    def test_allowed_packets
      (0..255).each do |type|
        packet = stub("packet", type: type)
        case type
        when 1..4, 6..19, 21..49 then assert(Net::SSH::Transport::Algorithms.allowed_packet?(packet), "#{type} should be allowed during key exchange")
        else assert(!Net::SSH::Transport::Algorithms.allowed_packet?(packet), "#{type} should not be allowed during key exchange")
        end
      end
    end

    def test_constructor_should_build_default_list_of_preferred_algorithms
      assert_equal ed_ec_host_keys + rsa_host_keys, algorithms[:host_key]
      assert_equal default_kex, algorithms[:kex]
      assert_equal chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com], algorithms[:encryption]
      assert_equal %w[hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha1], algorithms[:hmac]
      assert_equal %w[none zlib@openssh.com zlib], algorithms[:compression]
      assert_equal %w[], algorithms[:language]
    end

    def test_constructor_should_build_complete_list_of_algorithms_with_append_all_supported_algorithms
      assert_equal ed_ec_host_keys + rsa_host_keys + sha1_rsa_host_keys + %w[ssh-dss], algorithms(append_all_supported_algorithms: true)[:host_key]
      assert_equal x25519_kex + ec_kex + %w[diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha256 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1 diffie-hellman-group1-sha1], algorithms(append_all_supported_algorithms: true)[:kex]
      assert_equal chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-cbc aes192-cbc aes128-cbc rijndael-cbc@lysator.liu.se blowfish-ctr blowfish-cbc cast128-ctr cast128-cbc 3des-ctr 3des-cbc idea-cbc], algorithms(append_all_supported_algorithms: true)[:encryption]
      assert_equal %w[hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha1 hmac-sha2-512-96 hmac-sha2-256-96 hmac-sha1-96 hmac-ripemd160 hmac-ripemd160@openssh.com hmac-md5 hmac-md5-96], algorithms(append_all_supported_algorithms: true)[:hmac]
      assert_equal %w[none zlib@openssh.com zlib], algorithms(append_all_supported_algorithms: true)[:compression]
      assert_equal %w[], algorithms[:language]
    end

    def test_constructor_should_not_offer_group14_sha1_kex_by_default
      refute_includes algorithms[:kex], 'diffie-hellman-group14-sha1'
    end

    def test_constructor_with_kex_append_should_enable_group14_sha1
      assert_equal default_kex + %w[diffie-hellman-group14-sha1], algorithms(kex: '+diffie-hellman-group14-sha1')[:kex]
    end

    def test_plus_group14_sha1_kex_from_config_enables_group14_sha1
      config = Net::SSH::Config.translate(Net::SSH::Config.load('test/configs/kex_algorithms', 'sha1'))
      assert_equal default_kex + %w[diffie-hellman-group14-sha1], algorithms(config)[:kex]
    end

    def test_constructor_should_build_default_list_of_pubkey_algorithms
      assert_equal default_pubkey_algorithms, algorithms[:pubkey_algorithms]
    end

    def test_constructor_should_not_offer_sha1_rsa_pubkey_algorithms_by_default
      assert_empty algorithms[:pubkey_algorithms] & sha1_rsa_pubkey_algorithms
    end

    def test_constructor_should_offer_ssh_rsa_and_ssh_dss_pubkey_only_with_append_all_supported_algorithms
      assert_equal default_pubkey_algorithms + sha1_rsa_pubkey_algorithms + %w[ssh-dss],
                   algorithms(append_all_supported_algorithms: true)[:pubkey_algorithms]
    end

    def test_constructor_with_pubkey_algorithms_append_should_enable_ssh_rsa
      assert_equal default_pubkey_algorithms + %w[ssh-rsa], algorithms(pubkey_algorithms: %w[+ssh-rsa])[:pubkey_algorithms]
    end

    def test_constructor_should_keep_explicit_pubkey_algorithms
      assert_equal %w[rsa-sha2-256 ssh-rsa], algorithms(pubkey_algorithms: %w[rsa-sha2-256 ssh-rsa])[:pubkey_algorithms]
    end

    def test_pubkey_accepted_algorithms_from_config_replaces_list
      assert_equal %w[ssh-ed25519 rsa-sha2-512], pubkey_algorithms_for_host('plain')
    end

    def test_pubkey_accepted_algorithms_from_config_supports_additions
      assert_equal default_pubkey_algorithms + %w[ssh-dss], pubkey_algorithms_for_host('plus')
      assert_equal default_pubkey_algorithms + %w[ssh-dss], pubkey_algorithms_for_host('legacy')
    end

    def test_plus_ssh_rsa_from_config_enables_ssh_rsa_for_pubkey_and_host_key
      config = Net::SSH::Config.translate(Net::SSH::Config.load('test/configs/pubkey_accepted_algorithms', 'sha1'))
      assert_equal default_pubkey_algorithms + %w[ssh-rsa], algorithms(config)[:pubkey_algorithms]
      assert_equal ed_ec_host_keys + rsa_host_keys + %w[ssh-rsa], algorithms[:host_key]
    end

    def test_pubkey_accepted_algorithms_from_config_supports_removals_with_wildcard
      expected = default_pubkey_algorithms.reject { |alg| alg.start_with?('ssh-rsa', 'ecdsa-sha2-') }
      assert_equal expected, pubkey_algorithms_for_host('minus')
      assert_includes expected, 'sk-ecdsa-sha2-nistp256@openssh.com'
    end

    def test_pubkey_accepted_algorithms_from_config_supports_prepending
      assert_equal %w[rsa-sha2-512] + (default_pubkey_algorithms - %w[rsa-sha2-512]), pubkey_algorithms_for_host('caret')
    end

    def test_constructor_should_set_client_and_server_prefs_identically
      %w[encryption hmac compression language].each do |key|
        assert_equal algorithms[key.to_sym], algorithms[:"#{key}_client"], key
        assert_equal algorithms[key.to_sym], algorithms[:"#{key}_server"], key
      end
    end

    def test_constructor_with_preferred_host_key_type_should_put_preferred_host_key_type_first
      assert_equal %w[ssh-dss] + ed_ec_host_keys + rsa_host_keys + sha1_rsa_host_keys, algorithms(host_key: "ssh-dss", append_all_supported_algorithms: true)[:host_key]
    end

    def test_constructor_with_known_hosts_reporting_known_host_key_should_use_that_host_key_type
      Net::SSH::KnownHosts.expects(:search_for).with(
        "net.ssh.test,127.0.0.1",
        { user_known_hosts_file: "/dev/null", global_known_hosts_file: "/dev/null" }
      ).returns([stub("key", ssh_type: "ssh-dss")])
      assert_equal %w[ssh-dss] + ed_ec_host_keys + rsa_host_keys, algorithms[:host_key]
    end

    def test_constructor_should_not_offer_sha1_rsa_host_keys_by_default
      assert_empty algorithms[:host_key] & sha1_rsa_host_keys
    end

    def test_constructor_with_host_key_append_should_enable_ssh_rsa
      assert_equal ed_ec_host_keys + rsa_host_keys + %w[ssh-rsa], algorithms(host_key: '+ssh-rsa')[:host_key]
    end

    def test_constructor_with_explicit_ssh_rsa_host_key_should_use_only_that
      assert_equal %w[ssh-rsa], algorithms(host_key: 'ssh-rsa')[:host_key]
    end

    def test_constructor_with_known_rsa_host_key_should_prefer_rsa_sha2
      Net::SSH::KnownHosts.expects(:search_for).returns([stub("key", ssh_type: "ssh-rsa")])
      assert_equal rsa_host_keys + ed_ec_host_keys, algorithms[:host_key]
    end

    def test_constructor_with_known_rsa_host_key_and_ssh_rsa_enabled_should_prefer_all_rsa_algorithms
      Net::SSH::KnownHosts.expects(:search_for).returns([stub("key", ssh_type: "ssh-rsa")])
      assert_equal rsa_host_keys + %w[ssh-rsa] + ed_ec_host_keys + %w[ssh-rsa-cert-v01@openssh.com ssh-rsa-cert-v00@openssh.com ssh-dss],
                   algorithms(append_all_supported_algorithms: true)[:host_key]
    end

    def test_constructor_with_known_cert_authority_should_not_offer_sha1_rsa_certs
      Net::SSH::KnownHosts.expects(:search_for).returns([Net::SSH::HostKeyEntries::CertAuthority.new(stub("ca"))])
      assert_empty algorithms[:host_key] & sha1_rsa_host_keys
    end

    def test_key_exchange_when_server_only_supports_ssh_rsa_host_key_should_raise_error
      kexinit host_key: "ssh-rsa"
      transport.expect { |_t, buffer| assert_kexinit(buffer) }
      assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(kexinit) }
    end

    def test_key_exchange_when_server_supports_rsa_sha2_should_prefer_rsa_sha2_over_ssh_rsa
      kexinit host_key: "ssh-rsa,rsa-sha2-256,rsa-sha2-512"
      transport.expect do |_t, buffer|
        assert_kexinit(buffer)
        install_mock_key_exchange(buffer)
      end
      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)
      assert_equal "rsa-sha2-512", algorithms.host_key
    end

    def ed_host_keys
      if Net::SSH::Authentication::ED25519Loader::LOADED
        %w[ssh-ed25519-cert-v01@openssh.com ssh-ed25519]
      else
        []
      end
    end

    def ec_host_keys
      %w[ecdsa-sha2-nistp521-cert-v01@openssh.com
         ecdsa-sha2-nistp384-cert-v01@openssh.com
         ecdsa-sha2-nistp256-cert-v01@openssh.com
         ecdsa-sha2-nistp521
         ecdsa-sha2-nistp384
         ecdsa-sha2-nistp256]
    end

    def ed_ec_host_keys
      ed_host_keys + ec_host_keys
    end

    def rsa_host_keys
      %w[rsa-sha2-512 rsa-sha2-256]
    end

    def sha1_rsa_host_keys
      %w[ssh-rsa-cert-v01@openssh.com ssh-rsa-cert-v00@openssh.com ssh-rsa]
    end

    def test_constructor_with_unrecognized_host_key_type_should_return_whats_supported
      assert_equal ed_ec_host_keys + rsa_host_keys + sha1_rsa_host_keys + %w[ssh-dss],
                   algorithms(host_key: "bogus ssh-rsa", append_all_supported_algorithms: true)[:host_key]
    end

    def ec_kex
      %w[ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256]
    end

    def default_kex
      x25519_kex + ec_kex + %w[diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha256]
    end

    def x25519_kex
      if Net::SSH::Transport::Kex::Curve25519Sha256Loader::LOADED
        %w[curve25519-sha256 curve25519-sha256@libssh.org]
      else
        []
      end
    end

    def chacha_poly_cipher
      if Net::SSH::Transport::ChaCha20Poly1305CipherLoader::LOADED
        %w[chacha20-poly1305@openssh.com]
      else
        []
      end
    end

    def chacha_poly_cipher_str
      if chacha_poly_cipher.empty?
        ""
      else
        "#{chacha_poly_cipher.join(',')},"
      end
    end

    def test_constructor_with_preferred_kex_should_put_preferred_kex_first
      assert_equal %w[diffie-hellman-group1-sha1] + x25519_kex + ec_kex + %w[diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha256 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1],
                   algorithms(kex: "diffie-hellman-group1-sha1", append_all_supported_algorithms: true)[:kex]
    end

    def test_constructor_with_unrecognized_kex_should_not_raise_exception
      assert_equal %w[diffie-hellman-group1-sha1] + x25519_kex + ec_kex + %w[diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha256 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1],
                   algorithms(kex: %w[bogus diffie-hellman-group1-sha1], append_all_supported_algorithms: true)[:kex]
    end

    def test_constructor_with_preferred_kex_supports_additions
      assert_equal default_kex + %w[diffie-hellman-group1-sha1],
                   algorithms(kex: %w[+diffie-hellman-group1-sha1])[:kex]
    end

    def test_constructor_with_preferred_kex_supports_removals_with_wildcard
      assert_equal x25519_kex + ec_kex,
                   algorithms(kex: %w[-diffie-hellman-group*-sha256])[:kex]
    end

    def test_constructor_with_preferred_encryption_should_put_preferred_encryption_first
      assert_equal %w[aes256-cbc] + chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com aes192-cbc aes128-cbc rijndael-cbc@lysator.liu.se blowfish-ctr blowfish-cbc cast128-ctr cast128-cbc 3des-ctr 3des-cbc idea-cbc], algorithms(encryption: "aes256-cbc", append_all_supported_algorithms: true)[:encryption]
    end

    def test_constructor_with_multiple_preferred_encryption_should_put_all_preferred_encryption_first
      assert_equal %w[aes256-cbc 3des-cbc idea-cbc] + chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com aes192-cbc aes128-cbc rijndael-cbc@lysator.liu.se blowfish-ctr blowfish-cbc cast128-ctr cast128-cbc 3des-ctr], algorithms(encryption: %w[aes256-cbc 3des-cbc idea-cbc], append_all_supported_algorithms: true)[:encryption]
    end

    def test_constructor_with_unrecognized_encryption_should_keep_whats_supported
      assert_equal %w[aes256-cbc] + chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com aes192-cbc aes128-cbc rijndael-cbc@lysator.liu.se blowfish-ctr blowfish-cbc cast128-ctr cast128-cbc 3des-ctr 3des-cbc idea-cbc], algorithms(encryption: %w[bogus aes256-cbc], append_all_supported_algorithms: true)[:encryption]
    end

    def test_constructor_with_preferred_encryption_supports_additions
      assert_equal chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com 3des-cbc],
                   algorithms(encryption: %w[+3des-cbc])[:encryption]
    end

    def test_constructor_with_preferred_encryption_supports_removals_with_wildcard
      assert_equal chacha_poly_cipher + %w[aes256-gcm@openssh.com aes128-gcm@openssh.com],
                   algorithms(encryption: %w[-*-ctr -none])[:encryption]
    end

    def test_constructor_with_preferred_encryption_supports_removals_with_wildcard_from_all_supported
      assert_equal chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com cast128-ctr],
                   algorithms(encryption: %w[-rijndael-cbc@lysator.liu.se -blowfish-* -3des-* -*-cbc -none], append_all_supported_algorithms: true)[:encryption]
    end

    def test_constructor_with_preferred_encryption_removal_does_not_enable_non_default
      assert_equal chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com],
                   algorithms(encryption: %w[-aes128-ctr])[:encryption]
    end

    def test_constructor_with_preferred_encryption_removal_and_append_all_supported_algorithms
      assert_equal chacha_poly_cipher + %w[aes256-ctr aes192-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-cbc aes192-cbc aes128-cbc rijndael-cbc@lysator.liu.se blowfish-ctr blowfish-cbc cast128-ctr cast128-cbc 3des-ctr 3des-cbc idea-cbc],
                   algorithms(encryption: %w[-aes128-ctr], append_all_supported_algorithms: true)[:encryption]
    end

    def test_constructor_with_preferred_hmac_should_put_preferred_hmac_first
      assert_equal %w[hmac-md5-96 hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha1 hmac-sha2-512-96 hmac-sha2-256-96 hmac-sha1-96 hmac-ripemd160 hmac-ripemd160@openssh.com hmac-md5], algorithms(hmac: "hmac-md5-96", append_all_supported_algorithms: true)[:hmac]
    end

    def test_constructor_with_multiple_preferred_hmac_should_put_all_preferred_hmac_first
      assert_equal %w[hmac-md5-96 hmac-sha1-96 hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha1 hmac-sha2-512-96 hmac-sha2-256-96 hmac-ripemd160 hmac-ripemd160@openssh.com hmac-md5], algorithms(hmac: %w[hmac-md5-96 hmac-sha1-96], append_all_supported_algorithms: true)[:hmac]
    end

    def test_constructor_with_unrecognized_hmac_should_ignore_those
      assert_equal %w[hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha1 hmac-sha2-512-96 hmac-sha2-256-96 hmac-sha1-96 hmac-ripemd160 hmac-ripemd160@openssh.com hmac-md5 hmac-md5-96],
                   algorithms(hmac: "unknown hmac-md5-96", append_all_supported_algorithms: true)[:hmac]
    end

    def test_constructor_with_preferred_hmac_supports_additions
      assert_equal %w[hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha1 hmac-md5-96],
                   algorithms(hmac: %w[+hmac-md5-96 -none])[:hmac]
    end

    def test_constructor_with_preferred_hmac_supports_additions_with_append_all_supported_algorithms
      assert_equal %w[hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha1-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha1 hmac-md5-96 hmac-sha2-512-96 hmac-sha2-256-96 hmac-sha1-96 hmac-ripemd160 hmac-ripemd160@openssh.com hmac-md5],
                   algorithms(hmac: %w[+hmac-md5-96 -none], append_all_supported_algorithms: true)[:hmac]
    end

    def test_constructor_with_preferred_hmac_supports_removals_with_wildcard
      assert_equal %w[hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-256],
                   algorithms(hmac: %w[-hmac-sha1* -hmac-md5* -none])[:hmac]
    end

    def test_constructor_with_preferred_hmac_supports_removals_with_wildcard_from_all_supported
      assert_equal %w[hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com hmac-sha2-512 hmac-sha2-256 hmac-sha2-512-96 hmac-sha2-256-96 hmac-ripemd160 hmac-ripemd160@openssh.com],
                   algorithms(hmac: %w[-hmac-sha1* -hmac-md5* -none], append_all_supported_algorithms: true)[:hmac]
    end

    def test_constructor_with_preferred_compression_should_put_preferred_compression_first
      assert_equal %w[zlib none zlib@openssh.com], algorithms(compression: "zlib", append_all_supported_algorithms: true)[:compression]
    end

    def test_constructor_with_multiple_preferred_compression_should_put_all_preferred_compression_first
      assert_equal %w[zlib@openssh.com zlib none], algorithms(compression: %w[zlib@openssh.com zlib],
                                                              append_all_supported_algorithms: true)[:compression]
    end

    def test_constructor_with_general_preferred_compression_should_put_none_last
      assert_equal %w[zlib@openssh.com zlib none], algorithms(
        compression: true, append_all_supported_algorithms: true
      )[:compression]
    end

    def test_constructor_with_unrecognized_compression_should_return_whats_supported
      assert_equal %w[none zlib zlib@openssh.com], algorithms(compression: %w[bogus none zlib], append_all_supported_algorithms: true)[:compression]
    end

    def test_constructor_with_append_all_supported_algorithms_should_not_offer_none_cipher_or_mac
      algos = algorithms(append_all_supported_algorithms: true)
      refute_includes algos[:encryption], 'none'
      refute_includes algos[:hmac], 'none'
    end

    def test_constructor_with_preferred_mac_and_append_all_supported_algorithms_should_not_offer_none_mac
      refute_includes algorithms(hmac: %w[hmac-md5], append_all_supported_algorithms: true)[:hmac], 'none'
    end

    def test_constructor_with_append_all_supported_algorithms_should_still_offer_none_compression
      assert_includes algorithms(compression: true, append_all_supported_algorithms: true)[:compression], 'none'
    end

    def test_constructor_with_explicit_none_cipher_and_mac_should_offer_them
      algos = algorithms(encryption: '+none', hmac: '+none', append_all_supported_algorithms: true)
      assert_includes algos[:encryption], 'none'
      assert_includes algos[:hmac], 'none'
    end

    def test_constructor_with_none_in_full_list_should_offer_it
      algos = algorithms(encryption: %w[none aes256-ctr], hmac: %w[none], append_all_supported_algorithms: true)
      assert_equal %w[none aes256-ctr], algos[:encryption].first(2)
      assert_equal 'none', algos[:hmac].first
    end

    def test_constructor_with_deprecated_v00_host_key_should_warn
      Kernel.expects(:warn).with(regexp_matches(/ssh-rsa-cert-v00@openssh.com is deprecated and will be removed/)).once
      assert_includes algorithms(host_key: '+ssh-rsa-cert-v00@openssh.com')[:host_key], 'ssh-rsa-cert-v00@openssh.com'
    end

    def test_constructor_with_deprecated_v00_host_key_from_ssh_config_should_warn
      Kernel.expects(:warn).with(regexp_matches(/ssh-rsa-cert-v00@openssh.com is deprecated/)).once
      algorithms(Net::SSH::Config.translate('hostkeyalgorithms' => 'rsa-sha2-512,ssh-rsa-cert-v00@openssh.com'))
    end

    def test_constructor_with_append_all_supported_algorithms_should_not_warn_about_v00_host_key
      Kernel.expects(:warn).never
      assert_includes algorithms(append_all_supported_algorithms: true)[:host_key], 'ssh-rsa-cert-v00@openssh.com'
    end

    def test_constructor_removing_v00_host_key_should_not_warn
      Kernel.expects(:warn).never
      algorithms(host_key: '-ssh-rsa-cert-v00@openssh.com', append_all_supported_algorithms: true)
    end

    def test_key_exchange_negotiating_v00_host_key_should_warn
      kexinit host_key: "ssh-rsa-cert-v00@openssh.com"
      algorithms(append_all_supported_algorithms: true).stubs(:exchange_keys)
      transport.expect { |_t, buffer| assert_equal KEXINIT, buffer.type }
      Kernel.expects(:warn).with(regexp_matches(/ssh-rsa-cert-v00@openssh.com is deprecated/)).once
      algorithms.accept_kexinit(kexinit)
      assert_equal "ssh-rsa-cert-v00@openssh.com", algorithms.host_key
    end

    def test_constructor_with_host_key_append_to_default
      default_host_keys = Net::SSH::Transport::Algorithms::DEFAULT_ALGORITHMS[:host_key]
      assert_equal default_host_keys + %w[ssh-dss], algorithms(host_key: '+ssh-dss')[:host_key]
    end

    def test_constructor_with_host_key_prepend_to_default
      default_host_keys = Net::SSH::Transport::Algorithms::DEFAULT_ALGORITHMS[:host_key]
      default_host_keys = default_host_keys.dup.unshift('ssh-dss')
      assert_equal default_host_keys, algorithms(host_key: '^ssh-dss')[:host_key]
    end

    def test_constructor_with_host_key_removals_with_wildcard
      assert_equal ed_host_keys + %w[ecdsa-sha2-nistp521-cert-v01@openssh.com ecdsa-sha2-nistp384-cert-v01@openssh.com ecdsa-sha2-nistp256-cert-v01@openssh.com ecdsa-sha2-nistp521 ecdsa-sha2-nistp384 ecdsa-sha2-nistp256], algorithms(host_key: %w[-ssh-rsa* -ssh-dss -rsa-sha*])[:host_key]
    end

    def test_initial_state_should_be_neither_pending_nor_initialized
      assert !algorithms.pending?
      assert !algorithms.initialized?
    end

    def test_accept_kexinit_with_truncated_packet_should_raise_ssh_exception
      truncated = P(:byte, KEXINIT, :long, 0, :long, 0, :long, 0, :long, 0)
      assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(truncated) }
    end

    def test_key_exchange_when_initiated_by_server
      transport.expect do |_t, buffer|
        assert_kexinit(buffer)
        install_mock_key_exchange(buffer)
      end

      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)

      assert_exchange_results
    end

    def test_key_exchange_when_initiated_by_client
      state = nil
      transport.expect do |_t, buffer|
        assert_kexinit(buffer)
        state = :sent_kexinit
        install_mock_key_exchange(buffer)
      end

      algorithms.rekey!
      assert_equal state, :sent_kexinit
      assert algorithms.pending?

      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)

      assert_exchange_results
    end

    def test_key_exchange_when_server_does_not_support_preferred_kex_should_fallback_to_secondary
      kexinit kex: "diffie-hellman-group14-sha256"
      transport.expect do |_t, buffer|
        assert_kexinit(buffer)
        install_mock_key_exchange(buffer, kex: Net::SSH::Transport::Kex::DiffieHellmanGroup14SHA256)
      end
      algorithms.accept_kexinit(kexinit)
    end

    def test_key_exchange_should_not_negotiate_group14_sha1_by_default
      kexinit kex: "diffie-hellman-group14-sha1"
      transport.expect { |_t, buffer| assert_kexinit(buffer) }
      assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(kexinit) }
    end

    def test_key_exchange_should_negotiate_group14_sha1_when_enabled
      algorithms(kex: '+diffie-hellman-group14-sha1')
      kexinit kex: "diffie-hellman-group14-sha1"
      transport.expect do |_t, buffer|
        assert_kexinit(buffer, kex: (default_kex + %w[diffie-hellman-group14-sha1]).join(','))
        install_mock_key_exchange(buffer, kex: Net::SSH::Transport::Kex::DiffieHellmanGroup14SHA1)
      end
      algorithms.accept_kexinit(kexinit)
    end

    def test_key_exchange_when_server_does_not_support_any_preferred_kex_should_raise_error
      kexinit kex: "something-obscure"
      transport.expect { |_t, buffer| assert_kexinit(buffer) }
      assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(kexinit) }
    end

    def test_allow_when_not_pending_should_be_true_for_all_packets
      (0..255).each do |type|
        packet = stub("packet", type: type)
        assert algorithms.allow?(packet), type.to_s
      end
    end

    def test_allow_when_pending_should_be_true_only_for_packets_valid_during_key_exchange
      transport.expect!
      algorithms.rekey!
      assert algorithms.pending?

      (0..255).each do |type|
        packet = stub("packet", type: type)
        case type
        when 1..4, 6..19, 21..49 then assert(algorithms.allow?(packet), "#{type} should be allowed during key exchange")
        else assert(!algorithms.allow?(packet), "#{type} should not be allowed during key exchange")
        end
      end
    end

    def test_exchange_with_zlib_compression_enabled_sets_compression_to_standard
      algorithms compression: 'zlib'

      transport.expect do |_t, buffer|
        assert_kexinit(buffer, compression_client: 'zlib', compression_server: 'zlib')
        install_mock_key_exchange(buffer)
      end

      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)

      assert_equal :standard, transport.client_options[:compression]
      assert_equal :standard, transport.server_options[:compression]
    end

    def test_exchange_with_zlib_at_openssh_dot_com_compression_enabled_sets_compression_to_delayed
      algorithms compression: 'zlib@openssh.com'

      transport.expect do |_t, buffer|
        assert_kexinit(buffer, compression_client: 'zlib@openssh.com', compression_server: 'zlib@openssh.com')
        install_mock_key_exchange(buffer)
      end

      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)

      assert_equal :delayed, transport.client_options[:compression]
      assert_equal :delayed, transport.server_options[:compression]
    end

    # Verification for https://github.com/net-ssh/net-ssh/issues/483
    def test_that_algorithm_undefined_doesnt_throw_exception
      # Create a logger explicitly with DEBUG logging
      string_io = StringIO.new(String.new)
      debug_logger = Logger.new(string_io)
      debug_logger.level = Logger::DEBUG

      # Create our algorithm instance, with our logger sent to the underlying transport instance
      alg = algorithms(
        {},
        logger: debug_logger
      )

      # Here are our two lists - "ours" and "theirs"
      #
      # [a,b] overlap
      # [d]   "unsupported" values
      ours = %w[a b c]
      theirs = %w[a b d]

      ## Hit the method directly
      alg.send(
        :compose_algorithm_list,
        ours,
        ours,
        theirs
      )

      assert string_io.string.include?(%(unsupported algorithm: `["d"]'))
    end

    def test_algorithm_list_append
      assert_equal %w[a b c], algorithms.send(:compose_algorithm_list, %w[a b c d], %w[a b], %w[+c])
    end

    def test_algorithm_list_prepend
      assert_equal %w[a b c], algorithms.send(:compose_algorithm_list, %w[a b c d], %w[b c], %w[^a])
    end

    def test_algorithm_list_delete
      assert_equal %w[a b], algorithms.send(:compose_algorithm_list, %w[a b c d], %w[a b c], %w[-c])
    end

    def test_algorithm_list_multiple_operators
      assert_equal %w[a b c], algorithms.send(:compose_algorithm_list, %w[a b c d], %w[b d], %w[^a +c -d])
    end

    def test_algorithm_list_continue_append
      assert_equal %w[a b c d], algorithms.send(:compose_algorithm_list, %w[a b c d], %w[a b], %w[+c d])
    end

    def test_algorithm_list_continue_prepend
      assert_equal %w[a b c d], algorithms.send(:compose_algorithm_list, %w[a b c d], %w[c d], %w[^a b])
    end

    def test_algorithm_list_continue_delete
      assert_equal %w[a c], algorithms.send(:compose_algorithm_list, %w[a b c d], %w[a b c d], %w[-b d])
    end

    def test_host_key_format
      Kernel.stubs(:warn)
      algorithm_types = %w[
        ssh-rsa ssh-dss ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 ecdsa-sha2-nistp521
      ]

      algorithm_types
        .map { |t| [t, [0, 1].map { |n| "#{t}-cert-v0#{n}@openssh.com" }.push(t)] }
        .each do |type, host_keys|
          host_keys.each do |hk|
            algorithms(host_key: hk).instance_eval { @host_key = hk }
            assert_equal type, algorithms.host_key_format
          end
        end
    end

    private

    def install_mock_key_exchange(buffer, options = {})
      kex = options[:kex] || Net::SSH::Transport::Kex::DiffieHellmanGroupExchangeSHA256

      Net::SSH::Transport::Kex::MAP.each_value do |klass|
        next if klass == kex

        klass.expects(:new).never
      end

      kex.expects(:new)
         .with(algorithms, transport,
               client_version_string: Net::SSH::Transport::ServerVersion::PROTO_VERSION,
               server_version_string: transport.server_version.version,
               server_algorithm_packet: kexinit.to_s,
               client_algorithm_packet: buffer.to_s,
               need_bytes: 32,
               minimum_dh_bits: nil,
               logger: nil)
         .returns(stub("kex", exchange_keys: { shared_secret: shared_secret, session_id: session_id, hashing_algorithm: hashing_algorithm }))
    end

    def install_mock_algorithm_lookups(options = {})
      params = { shared: shared_secret.to_ssh, hash: session_id, digester: hashing_algorithm }
      key = key("C")

      cipher_client = OpenStruct.new(implicit_map?: false, id: :client_cipher) # rubocop:disable Style/OpenStructUse
      server_cipher = OpenStruct.new(implicit_map?: false, id: :server_cipher) # rubocop:disable Style/OpenStructUse
      Net::SSH::Transport::CipherFactory.expects(:get)
                                        .with(options[:client_cipher] || "aes256-ctr", params.merge(iv: key("A"), key: key, encrypt: true))
                                        .returns(cipher_client)

      key = key("D")
      Net::SSH::Transport::CipherFactory.expects(:get)
                                        .with(options[:server_cipher] || "aes256-ctr", params.merge(iv: key("B"), key: key, decrypt: true))
                                        .returns(server_cipher)

      Net::SSH::Transport::HMAC.expects(:get).with(options[:client_hmac] || "hmac-sha2-256", key("E"), params).returns(:client_hmac)
      Net::SSH::Transport::HMAC.expects(:get).with(options[:server_hmac] || "hmac-sha2-256", key("F"), params).returns(:server_hmac)
    end

    def shared_secret
      @shared_secret ||= dh_512bits_bn
    end

    def session_id
      @session_id ||= "this is the session id"
    end

    def hashing_algorithm
      OpenSSL::Digest::SHA1
    end

    def key(salt)
      hashing_algorithm.digest(shared_secret.to_ssh + session_id + salt + session_id)
    end

    def cipher(type, options = {})
      Net::SSH::Transport::CipherFactory.get(type, options)
    end

    def kexinit(options = {})
      @kexinit ||= P(:byte, KEXINIT,
                     :long, rand(0xFFFFFFFF), :long, rand(0xFFFFFFFF), :long, rand(0xFFFFFFFF), :long, rand(0xFFFFFFFF),
                     :string, options[:kex] || "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
                     :string, options[:host_key] || "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
                     :string, options[:encryption_client] || "aes256-ctr,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,idea-cbc",
                     :string, options[:encryption_server] || "aes256-ctr,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,idea-cbc",
                     :string, options[:hmac_client] || "hmac-sha2-256,hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96",
                     :string, options[:hmac_server] || "hmac-sha2-256,hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96",
                     :string, options[:compression_client] || "none,zlib@openssh.com,zlib",
                     :string, options[:compression_server] || "none,zlib@openssh.com,zlib",
                     :string, options[:language_client] || "",
                     :string, options[:language_server] || "",
                     :bool, options[:first_kex_follows])
    end

    def assert_kexinit(buffer, options = {})
      assert_equal KEXINIT, buffer.type
      assert_equal 16, buffer.read(16).length
      assert_equal options[:kex] || default_kex.join(','), buffer.read_string
      assert_equal options[:host_key] || (ed_ec_host_keys + rsa_host_keys).join(','), buffer.read_string
      assert_equal options[:encryption_client] || "#{chacha_poly_cipher_str}aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com", buffer.read_string
      assert_equal options[:encryption_server] || "#{chacha_poly_cipher_str}aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com", buffer.read_string
      assert_equal options[:hmac_client] || 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1', buffer.read_string
      assert_equal options[:hmac_server] || 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1', buffer.read_string
      assert_equal options[:compression_client] || 'none,zlib@openssh.com,zlib', buffer.read_string
      assert_equal options[:compression_server] || 'none,zlib@openssh.com,zlib', buffer.read_string
      assert_equal options[:language_client] || '', buffer.read_string
      assert_equal options[:language_server] || '', buffer.read_string
      assert_equal options[:first_kex_follows] || false, buffer.read_bool
    end

    def assert_exchange_results
      assert algorithms.initialized?
      assert !algorithms.pending?
      assert !transport.client_options[:compression]
      assert !transport.server_options[:compression]
      assert_equal :client_cipher, transport.client_options[:cipher].id
      assert_equal :server_cipher, transport.server_options[:cipher].id
      assert_equal :client_hmac, transport.client_options[:hmac]
      assert_equal :server_hmac, transport.server_options[:hmac]
    end

    def default_pubkey_algorithms
      %w[ssh-ed25519-cert-v01@openssh.com
         ecdsa-sha2-nistp256-cert-v01@openssh.com ecdsa-sha2-nistp384-cert-v01@openssh.com ecdsa-sha2-nistp521-cert-v01@openssh.com
         rsa-sha2-512-cert-v01@openssh.com rsa-sha2-256-cert-v01@openssh.com
         ssh-ed25519
         ecdsa-sha2-nistp256 ecdsa-sha2-nistp384 ecdsa-sha2-nistp521
         sk-ssh-ed25519@openssh.com sk-ecdsa-sha2-nistp256@openssh.com
         rsa-sha2-512 rsa-sha2-256]
    end

    def sha1_rsa_pubkey_algorithms
      %w[ssh-rsa-cert-v01@openssh.com ssh-rsa]
    end

    def pubkey_algorithms_for_host(host)
      config = Net::SSH::Config.translate(Net::SSH::Config.load('test/configs/pubkey_accepted_algorithms', host))
      algorithms(config)[:pubkey_algorithms]
    end

    def algorithms(algorithms_options = {}, transport_options = {})
      @algorithms ||= Net::SSH::Transport::Algorithms.new(
        transport(transport_options),
        algorithms_options
      )
    end

    def transport(transport_options = {})
      @transport ||= MockTransport.new(
        {
          user_known_hosts_file: '/dev/null',
          global_known_hosts_file: '/dev/null'
        }.merge(transport_options)
      )
    end
  end
end
