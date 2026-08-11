require_relative '../../common'
require 'net/ssh/transport/kex/mlkem768_x25519_sha256_loader'
require 'base64'

module Transport
  module Kex
    class TestMLKEM768X25519Sha256 < NetSSHTest
      include Net::SSH::Transport::Constants

      Algorithms = Struct.new(:host_key, :host_key_format, keyword_init: true)

      def setup
        skip 'ML-KEM-768/X25519 is not available' unless Net::SSH::Transport::Kex::MLKEM768X25519Sha256Loader::LOADED

        @algorithms = @connection = @kex = @packet_data = nil
        @server_blob = @server_host_key = @shared_secret = @signature = nil
      end

      def test_exchange_keys_should_return_expected_results_when_successful
        result = exchange!
        assert_equal session_id, result[:session_id]
        assert_equal server_host_key.to_blob, result[:server_key].to_blob
        assert_equal shared_secret.to_ssh, result[:shared_secret].to_ssh
        assert_equal digester, result[:hashing_algorithm]
      end

      def test_exchange_keys_with_unverifiable_host_should_raise_exception
        connection.verifier { false }
        assert_raises(Net::SSH::Exception) { exchange! }
      end

      def test_exchange_keys_with_signature_key_type_mismatch_should_raise_exception
        assert_raises(Net::SSH::Exception) { exchange! key_type: 'ssh-dss' }
      end

      def test_exchange_keys_when_server_signature_could_not_be_verified_should_raise_exception
        @signature = '1234567890'
        assert_raises(Net::SSH::Exception) { exchange! }
      end

      def test_exchange_keys_with_invalid_server_blob_should_raise_exception
        @server_blob = 'too short'
        assert_raises(Net::SSH::Exception) { exchange! signature: 'ignored' }
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
        Net::SSH::Transport::Kex::MLKEM768X25519Sha256
      end

      def key_type
        'ecdsa-sha2-nistp256'
      end

      def exchange!(options = {})
        connection.expect do |t, buffer|
          assert_equal KEXECDH_INIT, buffer.type
          @client_blob = buffer.read_string
          assert_equal subject::MLKEM_PUBLIC_KEY_BYTES + subject::X25519_KEY_BYTES, @client_blob.bytesize

          build_server_exchange unless @server_blob
          t.return(KEXECDH_REPLY,
                   :string, b(:key, server_host_key),
                   :string, @server_blob,
                   :string, b(:string, options[:key_type] || key_type,
                              :string, options[:signature] || signature))
          connection.expect do |t2, buffer2|
            assert_equal NEWKEYS, buffer2.type
            t2.return(NEWKEYS)
          end
        end
        kex.exchange_keys
      end

      def build_server_exchange
        mlkem_public_key = OpenSSL::PKey.new_raw_public_key(subject::MLKEM_ALGORITHM, client_mlkem_public_key)
        ciphertext, mlkem_secret = mlkem_public_key.encapsulate

        @server_x25519_key = OpenSSL::PKey.generate_key('X25519')
        client_x25519_key = OpenSSL::PKey.new_raw_public_key('X25519', client_x25519_public_key)
        x25519_secret = @server_x25519_key.derive(client_x25519_key)

        @server_blob = ciphertext + @server_x25519_key.raw_public_key
        hash = digester.digest(mlkem_secret + x25519_secret)
        @shared_secret = subject::StringEncodedSharedSecret.new(Net::SSH::Buffer.from(:string, hash).to_s)
      end

      def client_mlkem_public_key
        @client_blob.byteslice(0, subject::MLKEM_PUBLIC_KEY_BYTES)
      end

      def client_x25519_public_key
        @client_blob.byteslice(subject::MLKEM_PUBLIC_KEY_BYTES, subject::X25519_KEY_BYTES)
      end

      def kex
        @kex ||= subject.new(algorithms, connection, packet_data)
      end

      def algorithms(options = {})
        @algorithms ||= Algorithms.new(host_key: options[:server_host_key] || 'ecdsa-sha2-nistp256', host_key_format: options[:server_host_key] || 'ecdsa-sha2-nistp256')
      end

      def connection
        @connection ||= MockTransport.new
      end

      def server_host_key
        @server_host_key ||= OpenSSL::PKey::EC.generate('prime256v1')
      end

      def packet_data
        @packet_data ||= { client_version_string: 'client version string',
                           server_version_string: 'server version string',
                           server_algorithm_packet: 'server algorithm packet',
                           client_algorithm_packet: 'client algorithm packet' }
      end

      def shared_secret
        @shared_secret ||= build_server_exchange || @shared_secret
      end

      def session_id
        @session_id ||= begin
          buffer = Net::SSH::Buffer.from(:string, packet_data[:client_version_string],
                                         :string, packet_data[:server_version_string],
                                         :string, packet_data[:client_algorithm_packet],
                                         :string, packet_data[:server_algorithm_packet],
                                         :string, Net::SSH::Buffer.from(:key, server_host_key),
                                         :string, @client_blob,
                                         :string, @server_blob,
                                         :raw, shared_secret.to_ssh)
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
