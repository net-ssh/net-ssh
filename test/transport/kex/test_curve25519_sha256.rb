unless ENV['NET_SSH_NO_ED25519']
  require_relative '../../common'
  require 'transport/kex/test_diffie_hellman_group1_sha1'
  require 'net/ssh/transport/kex/curve25519_sha256_loader'
  require 'ostruct'

  module Transport
    module Kex
      class TestCurve25519Sha256 < NetSSHTest
        include Net::SSH::Transport::Constants

        def setup
          raise 'No X25519 set NET_SSH_NO_ED25519 to ignore this test' unless Net::SSH::Transport::Kex::Curve25519Sha256Loader::LOADED

          @ecdh = @algorithms = @connection = @server_key =
                                  @packet_data = @shared_secret = nil
        end

        def test_exchange_keys_should_return_expected_results_when_successful
          result = exchange!
          assert_equal session_id, result[:session_id]
          assert_equal server_host_key.to_blob, result[:server_key].to_blob
          assert_equal shared_secret, result[:shared_secret]
          assert_equal digester, result[:hashing_algorithm]
        end

        def test_exchange_keys_with_unverifiable_host_should_raise_exception
          connection.verifier { false }
          assert_raises(Net::SSH::Exception) { exchange! }
        end

        def test_exchange_keys_with_signature_key_type_mismatch_should_raise_exception
          assert_raises(Net::SSH::Exception) { exchange! key_type: 'ssh-dss' }
        end

        def test_exchange_keys_with_host_key_type_mismatch_should_raise_exception
          algorithms host_key: 'ssh-dss'
          assert_raises(Net::SSH::Exception) { exchange! key_type: 'ssh-dss' }
        end

        def test_exchange_keys_when_server_signature_could_not_be_verified_should_raise_exception
          @signature = '1234567890'
          assert_raises(Net::SSH::Exception) { exchange! }
        end

        def test_exchange_keys_should_pass_expected_parameters_to_host_key_verifier
          verified = false
          connection.verifier do |data|
            verified = true
            assert_equal server_host_key.to_blob, data[:key].to_blob

            blob = b(:key, data[:key]).to_s
            fingerprint = "SHA256:#{Base64.encode64(OpenSSL::Digest.digest('SHA256', blob)).chomp.gsub(/=+\z/, '')}"

            assert_equal blob, data[:key_blob]
            assert_equal fingerprint, data[:fingerprint]
            assert_equal connection, data[:session]

            true
          end

          assert_nothing_raised { exchange! }
          assert verified
        end

        private

        def digester
          OpenSSL::Digest::SHA256
        end

        def subject
          Net::SSH::Transport::Kex::Curve25519Sha256
        end

        def key_type
          'ecdsa-sha2-nistp256'
        end

        def exchange!(options = {})
          connection.expect do |t, buffer|
            assert_equal KEXECDH_INIT, buffer.type
            assert_equal ecdh.ecdh.public_key.to_bytes, buffer.read_string
            t.return(KEXECDH_REPLY,
                     :string, b(:key, server_host_key),
                     :string, server_ecdh_pubkey.to_bytes,
                     :string, b(:string, options[:key_type] || key_type,
                                :string, signature))
            connection.expect do |t2, buffer2|
              assert_equal NEWKEYS, buffer2.type
              t2.return(NEWKEYS)
            end
          end
          ecdh.exchange_keys
        end

        def ecdh
          @ecdh ||= subject.new(algorithms, connection, packet_data)
        end

        def algorithms(options = {})
          @algorithms ||= OpenStruct.new(host_key: options[:server_host_key] || 'ecdsa-sha2-nistp256', host_key_format: options[:server_host_key] || 'ecdsa-sha2-nistp256')
        end

        def connection
          @connection ||= MockTransport.new
        end

        def server_key
          @server_key ||= ::X25519::Scalar.generate
        end

        def server_host_key
          @server_host_key ||= OpenSSL::PKey::EC.new('prime256v1').generate_key
        end

        def packet_data
          @packet_data ||= { client_version_string: 'client version string',
                             server_version_string: 'server version string',
                             server_algorithm_packet: 'server algorithm packet',
                             client_algorithm_packet: 'client algorithm packet' }
        end

        def server_ecdh_pubkey
          @server_ecdh_pubkey ||= server_key.public_key
        end

        def shared_secret
          @shared_secret ||= OpenSSL::BN.new(ecdh.ecdh.diffie_hellman(server_ecdh_pubkey).to_bytes, 2)
        end

        def session_id
          @session_id ||= begin
            buffer = Net::SSH::Buffer.from(:string, packet_data[:client_version_string],
                                           :string, packet_data[:server_version_string],
                                           :string, packet_data[:client_algorithm_packet],
                                           :string, packet_data[:server_algorithm_packet],
                                           :string, Net::SSH::Buffer.from(:key, server_host_key),
                                           :string, ecdh.ecdh.public_key.to_bytes,
                                           :string, server_ecdh_pubkey.to_bytes,
                                           :bignum, shared_secret)
            digester.digest(buffer.to_s)
          end
        end

        def signature
          @signature ||= server_host_key.ssh_do_sign(session_id)
        end

        def b(*args)
          Net::SSH::Buffer.from(*args)
        end
      end
    end
  end
end
