require_relative '../common'
require 'net/ssh/authentication/key_manager'
require 'base64'

module Authentication
  class TestKeyManager < NetSSHTest
    def test_key_files_and_known_identities_are_empty_by_default
      assert manager.key_files.empty?
      assert manager.known_identities.empty?
    end

    def test_keycert_files_are_empty_by_default
      assert manager.keycert_files.empty?
    end

    def test_keycert_data_are_empty_by_default
      assert manager.keycert_data.empty?
    end

    def test_assume_agent_is_available_by_default
      assert manager.use_agent?
    end

    def test_add_ensures_list_is_unique
      manager.add "/first"
      manager.add "/second"
      manager.add "/third"
      manager.add "/second"
      assert_equal 3, manager.key_files.length
      final_files = manager.key_files.map { |item| item.split('/').last }
      assert_equal %w[first second third], final_files
    end

    def test_add_ensures_keycert_list_is_unique
      manager.add_keycert "/first"
      manager.add_keycert "/second"
      manager.add_keycert "/third"
      manager.add_keycert "/second"
      assert_equal 3, manager.keycert_files.length
      final_files = manager.keycert_files.map { |item| item.split('/').last }
      assert_equal %w[first second third], final_files
    end

    def test_add_ensures_keycert_data_list_is_unique
      manager.add_keycert_data "first"
      manager.add_keycert_data "second"
      manager.add_keycert_data "third"
      manager.add_keycert_data "second"
      assert_equal 3, manager.keycert_data.length
      assert_equal %w[first second third], manager.keycert_data
    end

    def test_use_agent_should_be_set_to_false_if_agent_could_not_be_found
      Net::SSH::Authentication::Agent.expects(:connect).raises(Net::SSH::Authentication::AgentNotAvailable)
      assert manager.use_agent?
      assert_nil manager.agent
      assert !manager.use_agent?
    end

    def test_agent_should_be_used_by_default
      assert manager.use_agent?
    end

    def test_agent_should_not_be_used_with_no_agent
      assert !manager(use_agent: false).use_agent?
    end

    def test_each_identity_should_load_from_key_files
      manager.stubs(:agent).returns(nil)
      first = File.expand_path("/first")
      second = File.expand_path("/second")
      stub_file_private_key first, rsa, rsa_pk
      stub_file_private_key second, dsa, dsa_pk

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 2, identities.length
      assert_equal rsa.to_blob, identities.first.to_blob
      assert_equal dsa.to_blob, identities.last.to_blob

      assert_equal({ from: :file, file: first, key: rsa }, manager.known_identities[rsa_pk])
      assert_equal({ from: :file, file: second, key: dsa }, manager.known_identities[dsa_pk])
    end

    def test_each_identity_should_load_from_implicit_cert_file
      manager.stubs(:agent).returns(nil)
      first = File.expand_path("/first")
      stub_implicit_file_cert first, rsa, rsa_cert

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 1, identities.length
      assert_equal rsa_cert.to_blob, identities.first.to_blob
      assert_equal({ from: :file, file: first }, manager.known_identities[rsa_cert])
    end

    def test_each_identity_should_use_cert_data
      manager.stubs(:agent).returns(nil)

      manager.add_key_data(rsa.to_pem)
      manager.add_keycert_data("ssh-rsa-cert-v01@openssh.com #{Base64.encode64(rsa_cert.to_blob)}")

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 2, identities.length
      assert_equal rsa.to_blob, identities[0].to_blob
      assert_equal rsa_cert.to_blob, identities[1].to_blob
    end

    def test_each_identity_should_load_from_explicit_cert_file_given_matching_key_is_loaded
      manager.stubs(:agent).returns(nil)
      stub_explicit_file_cert File.expand_path("/rsa-cert"), rsa_cert
      first = File.expand_path("/first")
      stub_file_private_key first, rsa, rsa_pk

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 2, identities.length
      assert_equal rsa.to_blob, identities.first.to_blob
      assert_equal rsa_cert.to_blob, identities.last.to_blob
      assert_equal({ from: :file, file: first, key: rsa }, manager.known_identities[rsa_pk])
      assert_equal({ from: :file, file: first, key: rsa }, manager.known_identities[rsa_cert])
    end

    def test_each_identity_should_ignore_explicit_cert_file_unless_matching_key_is_avaiable
      manager.stubs(:agent).returns(nil)
      stub_explicit_file_cert File.expand_path("/rsa-cert"), rsa_cert
      first = File.expand_path("/first")
      stub_file_private_key first, dsa, dsa_pk

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 1, identities.length
      assert_equal dsa.to_blob, identities.first.to_blob
      assert_equal({ from: :file, file: first, key: dsa }, manager.known_identities[dsa_pk])
    end

    def test_each_identity_should_not_prompt_for_passphrase_in_non_interactive_mode
      manager(non_interactive: true).stubs(:agent).returns(nil)
      first = File.expand_path("/first")
      stub_file_private_key first, rsa, rsa_pk, passphrase: :should_not_be_asked
      identities = []
      manager.each_identity { |identity| identities << identity }
      assert_equal(identities, [])
    end

    def test_identities_should_load_from_agent
      manager.stubs(:agent).returns(agent)

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 2, identities.length
      assert_equal rsa_pk.to_blob, identities.first.to_blob
      assert_equal dsa_pk.to_blob, identities.last.to_blob

      assert_equal({ from: :agent, identity: rsa_pk }, manager.known_identities[rsa_pk])
      assert_equal({ from: :agent, identity: dsa_pk }, manager.known_identities[dsa_pk])
    end

    def test_each_identity_should_match_explicit_keycert_with_agent_provided_identity
      manager.stubs(:agent).returns(agent)
      stub_explicit_file_cert File.expand_path("/cert"), rsa_cert

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 3, identities.length
      assert_equal rsa_pk.to_blob, identities[0].to_blob
      assert_equal dsa_pk.to_blob, identities[1].to_blob
      assert_equal rsa_cert.to_blob, identities[2].to_blob

      assert_equal({ from: :agent, identity: rsa_pk }, manager.known_identities[rsa_pk])
      assert_equal({ from: :agent, identity: dsa_pk }, manager.known_identities[dsa_pk])
      assert_equal({ from: :agent, identity: rsa_pk }, manager.known_identities[rsa_cert])
    end

    def test_identities_with_ecdsa_should_load_from_agent
      manager.stubs(:agent).returns(agent_with_ecdsa_keys)

      identities = []
      manager.each_identity { |identity| identities << identity }
      assert_equal 5, identities.length

      assert_equal rsa_pk.to_blob, identities[0].to_blob
      assert_equal dsa_pk.to_blob, identities[1].to_blob
      assert_equal ecdsa_sha2_nistp256_pk.to_blob, identities[2].to_blob
      assert_equal ecdsa_sha2_nistp384_pk.to_blob, identities[3].to_blob
      assert_equal ecdsa_sha2_nistp521_pk.to_blob, identities[4].to_blob

      assert_equal({ from: :agent, identity: rsa_pk }, manager.known_identities[rsa_pk])
      assert_equal({ from: :agent, identity: dsa_pk }, manager.known_identities[dsa_pk])
      assert_equal({ from: :agent, identity: ecdsa_sha2_nistp256_pk }, manager.known_identities[ecdsa_sha2_nistp256_pk])
      assert_equal({ from: :agent, identity: ecdsa_sha2_nistp384_pk }, manager.known_identities[ecdsa_sha2_nistp384_pk])
      assert_equal({ from: :agent, identity: ecdsa_sha2_nistp521_pk }, manager.known_identities[ecdsa_sha2_nistp521_pk])
    end

    def test_only_identities_with_key_files_should_load_from_agent_of_keys_only_set
      manager(keys_only: true).stubs(:agent).returns(agent)

      first = File.expand_path("/first")
      stub_file_private_key first, rsa, rsa_pk

      identities = []
      manager.each_identity { |identity| identities << identity }

      assert_equal 1, identities.length
      assert_equal rsa_pk.to_blob, identities.first.to_blob

      assert_equal({ from: :agent, identity: rsa_pk }, manager.known_identities[rsa_pk])
      assert manager.use_agent?
    end

    def test_identities_without_public_key_files_should_not_be_touched_if_identity_loaded_from_agent
      manager.stubs(:agent).returns(agent_with_ecdsa_keys)

      first = File.expand_path("/first")
      stub_file_private_key first, rsa, rsa_pk
      second = File.expand_path("/second")
      stub_file_private_key second, dsa, dsa_pk, passphrase: :should_not_be_asked
      key3 = File.expand_path("/key3")
      stub_file_private_key key3, ecdsa_sha2_nistp256, ecdsa_sha2_nistp256_pk

      identities = []
      manager.each_identity do |identity|
        identities << identity
        break if manager.known_identities[identity][:from] == :agent
      end

      assert_equal 1, identities.length
      assert_equal rsa_pk.to_blob, identities.first.to_blob
    end

    def test_sign_with_agent_originated_key_should_request_signature_from_agent
      manager.stubs(:agent).returns(agent)
      manager.each_identity { |identity| } # preload the known_identities
      agent.expects(:sign).with(rsa_pk, "hello, world").returns("abcxyz123")
      assert_equal "abcxyz123", manager.sign(rsa_pk, "hello, world")
    end

    def test_sign_with_agent_originated_key_should_be_signable_through_explicitly_loaded_cert
      stub_explicit_file_cert File.expand_path("/cert"), rsa_cert
      manager.stubs(:agent).returns(agent)
      manager.each_identity { |identity| } # preload the known_identities
      agent.expects(:sign).with(rsa_pk, "hello, world").returns("abcxyz123")
      assert_equal "abcxyz123", manager.sign(rsa_cert, "hello, world")
    end

    def test_sign_with_file_originated_key_should_load_private_key_and_sign_with_it
      manager.stubs(:agent).returns(nil)
      first = File.expand_path("/first")
      stub_file_private_key first, rsa(512), rsa_pk
      rsa.expects(:ssh_do_sign).with("hello, world").returns("abcxyz123")
      manager.each_identity { |identity| } # preload the known_identities
      assert_equal "\0\0\0\assh-rsa\0\0\0\011abcxyz123", manager.sign(rsa_pk, "hello, world")
    end

    def test_sign_with_file_originated_key_should_raise_key_manager_error_if_unloadable
      manager.known_identities[rsa] = { from: :file, file: "/first" }

      Net::SSH::KeyFactory.expects(:load_private_key).raises(OpenSSL::PKey::RSAError)

      assert_raises Net::SSH::Authentication::KeyManagerError do
        manager.sign(rsa, "hello, world")
      end
    end

    def test_sign_passes_password_prompt_to_key_factory
      manager.known_identities[rsa] = { from: :file, file: "/first" }
      Net::SSH::KeyFactory.expects(:load_private_key).with('/first', nil, true, prompt).returns(rsa)
      manager.sign(rsa, "hello, world")
    end

    private

    def stub_file_private_key(name, key, public_key, options = {})
      manager.add(name)
      File.stubs(:file?).with(name).returns(true)
      File.stubs(:readable?).with(name).returns(true)
      File.stubs(:file?).with(name + ".pub").returns(true)
      File.stubs(:readable?).with(name + ".pub").returns(false)
      File.stubs(:file?).with(name + "-cert.pub").returns(false)

      case options.fetch(:passphrase, :indifferently)
      when :should_be_asked
        Net::SSH::KeyFactory.expects(:load_private_key).with(name, nil, false, prompt).raises(OpenSSL::PKey::RSAError).at_least_once
        Net::SSH::KeyFactory.expects(:load_private_key).with(name, nil, true, prompt).returns(key).at_least_once
      when :should_not_be_asked
        Net::SSH::KeyFactory.expects(:load_private_key).with(name, nil, false, prompt).raises(OpenSSL::PKey::RSAError).at_least_once
        Net::SSH::KeyFactory.expects(:load_private_key).with(name, nil, true, prompt).never
      else # :indifferently
        Net::SSH::KeyFactory.expects(:load_private_key).with(name, nil, any_of(true, false), prompt).returns(key).at_least_once
      end

      # We need to stub #public_key as we rely on object identity to
      # access #known_identities by private_key
      key.stubs(:public_key).returns(public_key)
    end

    def stub_file_public_key(name, key)
      manager.add(name)
      File.stubs(:file?).with(name).returns(true)
      File.stubs(:readable?).with(name).returns(true)
      File.stubs(:file?).with(name + ".pub").returns(true)
      File.stubs(:readable?).with(name + ".pub").returns(true)
      File.stubs(:file?).with(name + "-cert.pub").returns(false)

      Net::SSH::KeyFactory.expects(:load_public_key).with(name + ".pub").returns(key).at_least_once
    end

    def stub_implicit_file_cert(name, key, cert)
      manager.add(name)
      File.stubs(:file?).with(name).returns(true)
      File.stubs(:readable?).with(name).returns(true)
      File.stubs(:file?).with(name + ".pub").returns(true)
      File.stubs(:readable?).with(name + ".pub").returns(true)
      File.stubs(:file?).with(name + "-cert.pub").returns(true)
      File.stubs(:readable?).with(name + "-cert.pub").returns(true)

      Net::SSH::KeyFactory.expects(:load_public_key).with(name + "-cert.pub").returns(cert).at_least_once
    end

    def stub_explicit_file_cert(name, cert)
      manager.add_keycert(name)
      File.stubs(:file?).with(name).returns(true)
      File.stubs(:readable?).with(name).returns(true)

      Net::SSH::KeyFactory.expects(:load_public_key).with(name).returns(cert).at_least_once
    end

    def rsa_cert
      @cert ||= begin
        cert = Net::SSH::Authentication::Certificate.new
        cert.type = :user
        cert.key = rsa_pk
        cert.serial = 1
        cert.key_id = "test key"
        cert.valid_principals = %w[test user]
        cert.valid_before = Time.now - 86400
        cert.valid_after = Time.now + 86400
        cert.critical_options = {}
        cert.extensions = {}
        cert.reserved = ''
        cert.sign!(OpenSSL::PKey::DSA.new(1024))
        cert
      end
    end

    def rsa(size = 512)
      @rsa ||= OpenSSL::PKey::RSA.new(size)
    end

    def dsa
      @dsa ||= OpenSSL::PKey::DSA.new(1024)
    end

    def ecdsa_sha2_nistp256
      @ecdsa_sha2_nistp256 ||= OpenSSL::PKey::EC.generate('prime256v1')
    end

    def ecdsa_sha2_nistp384
      @ecdsa_sha2_nistp384 ||= OpenSSL::PKey::EC.generate('secp384r1')
    end

    def ecdsa_sha2_nistp521
      @ecdsa_sha2_nistp521 ||= OpenSSL::PKey::EC.generate('secp521r1')
    end

    def rsa_pk
      @rsa_pk ||= rsa.public_key
    end

    def dsa_pk
      @dsa_pk ||= dsa.public_key
    end

    def ecdsa_sha2_nistp256_pk
      @ecdsa_sha2_nistp256_pk ||= ecdsa_sha2_nistp256.public_key
    end

    def ecdsa_sha2_nistp384_pk
      @ecdsa_sha2_nistp384_pk ||= ecdsa_sha2_nistp521.public_key
    end

    def ecdsa_sha2_nistp521_pk
      @ecdsa_sha2_nistp521_pk ||= ecdsa_sha2_nistp521.public_key
    end

    def agent
      @agent ||= stub("agent", identities: [rsa_pk, dsa_pk])
    end

    def agent_with_ecdsa_keys
      @agent ||= stub("agent", identities: [rsa_pk, dsa_pk,
                                            ecdsa_sha2_nistp256_pk,
                                            ecdsa_sha2_nistp384_pk,
                                            ecdsa_sha2_nistp521_pk])
    end

    def prompt
      @promp ||= MockPrompt.new
    end

    def manager(options = {})
      @manager ||= Net::SSH::Authentication::KeyManager.new(nil, { password_prompt: prompt }.merge(options))
    end
  end
end
