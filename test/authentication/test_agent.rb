require_relative '../common'
require 'net/ssh/authentication/agent'

module Authentication

  class TestAgent < NetSSHTest
    SSH2_AGENT_REQUEST_VERSION       = 1
    SSH2_AGENT_REQUEST_IDENTITIES    = 11
    SSH2_AGENT_IDENTITIES_ANSWER     = 12
    SSH2_AGENT_SIGN_REQUEST          = 13
    SSH2_AGENT_SIGN_RESPONSE         = 14
    SSH2_AGENT_ADD_IDENTITY          = 17
    SSH2_AGENT_REMOVE_IDENTITY       = 18
    SSH2_AGENT_REMOVE_ALL_IDENTITIES = 19
    SSH2_AGENT_ADD_ID_CONSTRAINED    = 25
    SSH2_AGENT_FAILURE               = 30
    SSH2_AGENT_VERSION_RESPONSE      = 103

    SSH_COM_AGENT2_FAILURE = 102

    SSH_AGENT_REQUEST_RSA_IDENTITIES = 1
    SSH_AGENT_RSA_IDENTITIES_ANSWER  = 2
    SSH_AGENT_FAILURE                = 5
    SSH_AGENT_SUCCESS                = 6

    SSH_AGENT_CONSTRAIN_LIFETIME = 1
    SSH_AGENT_CONSTRAIN_CONFIRM  = 2

    ED25519 = <<-EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDuVIPDUXcVkXOyNAaFsotbySHLNG/Gw6gc3j2k2zcRVAAAAKD6bG5++mxu
fgAAAAtzc2gtZWQyNTUxOQAAACDuVIPDUXcVkXOyNAaFsotbySHLNG/Gw6gc3j2k2zcRVA
AAAEAydU4FtZ9+5o5Y/m1aPNHFda37Fm0Us5FlUKx50tWw+e5Ug8NRdxWRc7I0BoWyi1vJ
Ics0b8bDqBzePaTbNxFUAAAAGmJhcnRsZUBCYXJ0bGVzLU1hY0Jvb2stUHJvAQID
-----END OPENSSH PRIVATE KEY-----
EOF

    # rubocop:disable LineLength
    CERT = "\x00\x00\x00\x1Cssh-rsa-cert-v01@openssh.com\x00\x00\x00 Ir\xB9\xC9\x94l\x0ER\xA1h\xF5\xFDx\xB2J\xC6g\eHS\xDD\x162\x86\xF1\x90%\\$rf\xAF\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x01\x00\xB3R\xBC\xF8\xEA\xA30\x90\x87\x85\xF6m\x80\xFB\x7F\x96%\xC0h\x85$\x05\x05J\x9BE\xD9\xDE\x81\xC0\xC9\xC2\xC0\x0F'\xD1TR\xCBb\xCD\xD0o\xA0\x15Q\x8B\xF26t\xC9!8\x85\xD2\f'\xC6\x14u\x1De\x90qyXl\a\x06\xA7\xD0\xB8 \xE1\xB3IP\xDE\xB5\xBE\x19\x0E\x97-M\xFDJT\x81\xE2\x8E>\xCD\x18\x9CJz\x1C\xB5}LsO\xF3\xAC\xAA\r\xAB\xF9\xD4\x83\x8DQ\x82\xE7F\xA4\x9F\x1C\x9A\xC5\xC3Y\x84k\x86\ef\xD7\x84\xE3\v\rlG\x15ya\xB0=\xDF\x11\x8D\x0FtZ/p\xBB\xB7g\xF5\xEBF8\xF5\x05}}\xDB\xFA\xA34dw\xE5\x80\xBC!=\x0E\x96\x18\bF\x10\a{\xFF\x9D2\xCA\xAAnu\x82\x82\xBA-F\x8C\x12\xBB\x04+nh\xE9N\xAF\fe\x16\x00Q\x9C\x1C\xCB\x94\x02\x8CQ\xFB,H[\x96\xF1Z4\nY]@\xE0\bs\x9Bh\x0E\xAA~\x105\x99\\\x8C\xA7q\x1A=\xA9\x9D\xBAbx\xF5`[\x8Aw\x80\b\xE0vy\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00\x01\x00\x00\x00\x06foobar\x00\x00\x00\b\x00\x00\x00\x04root\x00\x00\x00\x00Xk\\\x1C\x00\x00\x00\x00ZK>g\x00\x00\x00#\x00\x00\x00\rforce-command\x00\x00\x00\x0E\x00\x00\x00\n/bin/false\x00\x00\x00c\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x16permit-port-forwarding\x00\x00\x00\x00\x00\x00\x00\npermit-pty\x00\x00\x00\x00\x00\x00\x00\x0Epermit-user-rc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x17\x00\x00\x00\assh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x01\x00\x9DRU\x0E\x83\x8Eb}\x81vOn\xCA\xBA\x01%\xFE\x87\x80b\xB5\x98R%\xA9(\xC1\xAE\xEFq|\x82L\xADQ?\x1D\xC6o\xB8\xD8pI\e\xFC\xF8\xFE^\xAD*\xA4u;\x99S\fc\x11\xBE\xFD\x047B\x1C\xF2h\xBA\xB1\xB0\n\x12F\e\x16\xF7Z\x8D\xD3\xF2f\xC0\x1C\xD8\xBE\xCC\x82\x85Qka$\xB6\xBD\x1C)\x85B\xAAf\xC8\xF3V*\xC3\x1C\xAA\xDC\xC3I\xDDe\xEFu\x02M\x12\x1A\xE2};he\x9D\xB5\xA47\xE4\x12\x8F\xE0\xF1\xA5\x91/\xFB\xEA\t\x0F \x1E\xB4B@+6\x1F\xBD\xA7\xA9u\x80\x19\xAA\xAC\xFFK\\F\x8C\xD9u\f?\xB9#[M\xDF\xB0\xFC\xE8\xF6J\x98\xA4\x99\x8F\xF9]\x88\x1D|A%\xAB\e\x0EN\xAA\xD3 \xCF\xA7}c\xDE\xF5\xBA4\xC8\xD2\x81(\x13\xB3\x94@fC\xDC\xDF\xFD\xA1\e$?\x13\xA9m\xEB*\xCA'\xB3\x19\x19\xF0\xD2\xB3P\x00\x96ou\xE90\xC4-\x1F\xCF\x1Aw\x034\xC6\xDF\xA7\x8C\xCA^Ix\x15\xFA\x9A+\x00\x00\x01\x0F\x00\x00\x00\assh-rsa\x00\x00\x01\x00I\b%\x01\xB2\xCC\x87\xD7\e\xC5\x88\x93|\x9D\xEC}\xA4\x86\xD7\xBB\xB6\xD3\x93\xFD\\\xC73\xC2*\aV\xA2\x81\x05J\x91\x9AEKV\n\xB4\xEB\xF3\xBC\xBAr\x16\xE5\x9A\xB9\xDC(0\xB4\x1C\x9F\"\x9E\xF9\x91\xD0\x1F\x9Cp\r*\xE3\x8A\xD3\xB9W$[OI\xD2\x8F8\x9B\xA4\x9E\xFFuGg\x00\xA5\xCD\r\xDB\x95\xEE)_\xC3\xBCi\xA2\xCC\r\x86\xFD\xE9\xE6\x188\x92\xFD\xCC\n\x98t\x8C\x16\xF4O\xF6\xD5\xD4\xB7\\\xB95\x19\xA3\xBBW\xF3\xF7r<\xE6\x8C\xFC\xE5\x9F\xBF\xE0\xBF\x06\xE7v\xF2\x8Ek\xA4\x02\xB6fMd\xA5e\x87\xE1\x93\xF5\x81\xCF\xDF\x88\xDC\a\xA2\e\xD5\xCA\x14\xB2>\xF4\x8F|\xE5-w\xF5\x85\xD0\xF1F((\xD1\xEEE&\x1D\xA2+\xEC\x93\xE7\xC7\xAE\xE38\xE4\xAE\xF7 \xED\xC6\r\xD6\x1A\xE1#<\xA2)j\xB3TA\\\xFF;\xC5\xA6Tu\xAAap\xDE\xF4\xF7 p\xCA\xD2\xBA\xDC\xCDv\x17\xC2\xBCQ\xDF\xAB7^\xA1G\x18\xB9\xB2F\x81\x9Fq\x92\xD3".force_encoding('BINARY')

    def setup
      @original, ENV['SSH_AUTH_SOCK'] = ENV['SSH_AUTH_SOCK'], "/path/to/ssh.agent.sock"
    end

    def teardown
      ENV['SSH_AUTH_SOCK'] = @original
    end

    def test_connect_should_use_agent_factory_to_determine_connection_type
      factory.expects(:open).with("/path/to/ssh.agent.sock").returns(socket)
      agent(false).connect!
    end

    def test_connect_should_use_agent_socket_factory_instead_of_factory
      assert_equal agent.connect!, socket
      assert_equal agent.connect!(agent_socket_factory), "/foo/bar.sock"
    end

    def test_connect_should_raise_error_if_connection_could_not_be_established
      factory.expects(:open).raises(SocketError)
      assert_raises(Net::SSH::Authentication::AgentNotAvailable) { agent(false).connect! }
    end

    def test_negotiate_should_raise_error_if_ssh2_agent_response_received
      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_VERSION, type
        assert_equal Net::SSH::Transport::ServerVersion::PROTO_VERSION, buffer.read_string
        s.return(SSH2_AGENT_VERSION_RESPONSE)
      end
      assert_raises(Net::SSH::Authentication::AgentNotAvailable) { agent.negotiate! }
    end

    def test_negotiate_should_raise_error_if_response_was_unexpected
      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_VERSION, type
        s.return(255)
      end
      assert_raises(Net::SSH::Authentication::AgentNotAvailable) { agent.negotiate! }
    end

    def test_negotiate_should_be_successful_with_expected_response
      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_VERSION, type
        s.return(SSH_AGENT_RSA_IDENTITIES_ANSWER)
      end
      assert_nothing_raised { agent(:connect).negotiate! }
    end

    def test_identities_should_fail_if_SSH_AGENT_FAILURE_received
      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_IDENTITIES, type
        s.return(SSH_AGENT_FAILURE)
      end
      assert_raises(Net::SSH::Authentication::AgentError) { agent.identities }
    end

    def test_identities_should_fail_if_SSH2_AGENT_FAILURE_received
      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_IDENTITIES, type
        s.return(SSH2_AGENT_FAILURE)
      end
      assert_raises(Net::SSH::Authentication::AgentError) { agent.identities }
    end

    def test_identities_should_fail_if_SSH_COM_AGENT2_FAILURE_received
      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_IDENTITIES, type
        s.return(SSH_COM_AGENT2_FAILURE)
      end
      assert_raises(Net::SSH::Authentication::AgentError) { agent.identities }
    end

    def test_identities_should_fail_if_response_is_not_SSH2_AGENT_IDENTITIES_ANSWER
      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_IDENTITIES, type
        s.return(255)
      end
      assert_raises(Net::SSH::Authentication::AgentError) { agent.identities }
    end

    def test_identities_should_augment_identities_with_comment_field
      key1 = key
      key2 = OpenSSL::PKey::DSA.new(512)

      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_IDENTITIES, type
        s.return(SSH2_AGENT_IDENTITIES_ANSWER, :long, 2, :string, Net::SSH::Buffer.from(:key, key1), :string, "My favorite key", :string, Net::SSH::Buffer.from(:key, key2), :string, "Okay, but not the best")
      end

      result = agent.identities
      assert_equal key1.to_blob, result.first.to_blob
      assert_equal key2.to_blob, result.last.to_blob
      assert_equal "My favorite key", result.first.comment
      assert_equal "Okay, but not the best", result.last.comment
    end

    def test_identities_should_ignore_unimplemented_ones
      key1 = key
      key2 = OpenSSL::PKey::DSA.new(512)
      key2.to_blob[0..5] = 'badkey'
      key3 = OpenSSL::PKey::DSA.new(512)

      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_IDENTITIES, type
        s.return(SSH2_AGENT_IDENTITIES_ANSWER, :long, 3, :string, Net::SSH::Buffer.from(:key, key1), :string, "My favorite key", :string, Net::SSH::Buffer.from(:key, key2), :string, "bad", :string, Net::SSH::Buffer.from(:key, key3), :string, "Okay, but not the best")
      end

      result = agent.identities
      assert_equal 2,result.size
      assert_equal key1.to_blob, result.first.to_blob
      assert_equal key3.to_blob, result.last.to_blob
      assert_equal "My favorite key", result.first.comment
      assert_equal "Okay, but not the best", result.last.comment
    end

    def test_identities_should_ignore_invalid_ones
      key1 = key
      key2_bad = Net::SSH::Buffer.new("")
      key3 = OpenSSL::PKey::DSA.new(512)

      socket.expect do |s, type, buffer|
        assert_equal SSH2_AGENT_REQUEST_IDENTITIES, type
        s.return(SSH2_AGENT_IDENTITIES_ANSWER, :long, 3, :string, Net::SSH::Buffer.from(:key, key1), :string, "My favorite key", :string, key2_bad, :string, "bad", :string, Net::SSH::Buffer.from(:key, key3), :string, "Okay, but not the best")
      end

      result = agent.identities
      assert_equal 2,result.size
      assert_equal key1.to_blob, result.first.to_blob
      assert_equal key3.to_blob, result.last.to_blob
      assert_equal "My favorite key", result.first.comment
      assert_equal "Okay, but not the best", result.last.comment
    end

    def test_close_should_close_socket
      socket.expects(:close)
      agent.close
    end

    def test_sign_should_fail_if_response_is_SSH_AGENT_FAILURE
      socket.expect { |s,| s.return(SSH_AGENT_FAILURE) }
      assert_raises(Net::SSH::Authentication::AgentError) { agent.sign(key, "hello world") }
    end

    def test_sign_should_fail_if_response_is_SSH2_AGENT_FAILURE
      socket.expect { |s,| s.return(SSH2_AGENT_FAILURE) }
      assert_raises(Net::SSH::Authentication::AgentError) { agent.sign(key, "hello world") }
    end

    def test_sign_should_fail_if_response_is_SSH_COM_AGENT2_FAILURE
      socket.expect { |s,| s.return(SSH_COM_AGENT2_FAILURE) }
      assert_raises(Net::SSH::Authentication::AgentError) { agent.sign(key, "hello world") }
    end

    def test_sign_should_fail_if_response_is_not_SSH2_AGENT_SIGN_RESPONSE
      socket.expect { |s,| s.return(255) }
      assert_raises(Net::SSH::Authentication::AgentError) { agent.sign(key, "hello world") }
    end

    def test_sign_should_return_signed_data_from_agent
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_SIGN_REQUEST, type
        assert_equal key.to_blob, Net::SSH::Buffer.new(buffer.read_string).read_key.to_blob
        assert_equal "hello world", buffer.read_string
        assert_equal 0, buffer.read_long

        s.return(SSH2_AGENT_SIGN_RESPONSE, :string, "abcxyz123")
      end

      assert_equal "abcxyz123", agent.sign(key, "hello world")
    end

    def test_add_rsa_identity_with_constraints
      rsa = OpenSSL::PKey::RSA.new(512)
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_ID_CONSTRAINED, type
        assert_equal buffer.read_string, "ssh-rsa"
        assert_equal buffer.read_bignum.to_s, rsa.n.to_s
        assert_equal buffer.read_bignum.to_s, rsa.e.to_s
        assert_equal buffer.read_bignum.to_s, rsa.d.to_s
        assert_equal buffer.read_bignum.to_s, rsa.iqmp.to_s
        assert_equal buffer.read_bignum.to_s, rsa.p.to_s
        assert_equal buffer.read_bignum.to_s, rsa.q.to_s
        assert_equal 'foobar', buffer.read_string
        assert_equal SSH_AGENT_CONSTRAIN_LIFETIME, buffer.read_byte
        assert_equal 42, buffer.read_long
        assert_equal SSH_AGENT_CONSTRAIN_CONFIRM, buffer.read_byte
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(rsa, "foobar", lifetime: 42, confirm: true)
    end

    def test_add_rsa_cert_identity
      cert = make_cert(OpenSSL::PKey::RSA.new(512))
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_IDENTITY, type
        assert_equal buffer.read_string, "ssh-rsa-cert-v01@openssh.com"
        assert_equal buffer.read_string, cert.to_blob
        assert_equal buffer.read_bignum.to_s, cert.key.d.to_s
        assert_equal buffer.read_bignum.to_s, cert.key.iqmp.to_s
        assert_equal buffer.read_bignum.to_s, cert.key.p.to_s
        assert_equal buffer.read_bignum.to_s, cert.key.q.to_s
        assert_equal 'foobar', buffer.read_string
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(cert, "foobar")
    end

    def test_add_dsa_identity
      dsa = OpenSSL::PKey::DSA.new(512)
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_IDENTITY, type
        assert_equal buffer.read_string, "ssh-dss"
        assert_equal buffer.read_bignum.to_s, dsa.p.to_s
        assert_equal buffer.read_bignum.to_s, dsa.q.to_s
        assert_equal buffer.read_bignum.to_s, dsa.g.to_s
        assert_equal buffer.read_bignum.to_s, dsa.pub_key.to_s
        assert_equal buffer.read_bignum.to_s, dsa.priv_key.to_s
        assert_equal 'foobar', buffer.read_string
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(dsa, "foobar")
    end

    def test_add_dsa_cert_identity
      cert = make_cert(OpenSSL::PKey::DSA.new(512))
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_IDENTITY, type
        assert_equal buffer.read_string, "ssh-dss-cert-v01@openssh.com"
        assert_equal buffer.read_string, cert.to_blob
        assert_equal buffer.read_bignum.to_s, cert.key.priv_key.to_s
        assert_equal 'foobar', buffer.read_string
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(cert, "foobar")
    end

    def test_add_ecdsa_identity
      return unless defined?(OpenSSL::PKey::EC)
      ecdsa = OpenSSL::PKey::EC.new("prime256v1").generate_key
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_IDENTITY, type
        assert_equal buffer.read_string, "ecdsa-sha2-nistp256"
        assert_equal buffer.read_string, "nistp256"
        assert_equal buffer.read_string, ecdsa.public_key.to_bn.to_s(2)
        assert_equal buffer.read_bignum, ecdsa.private_key
        assert_equal 'foobar', buffer.read_string
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(ecdsa, "foobar")
    end

    def test_add_ecdsa_cert_identity
      return unless defined?(OpenSSL::PKey::EC)
      cert = make_cert(OpenSSL::PKey::EC.new("prime256v1").generate_key)
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_IDENTITY, type
        assert_equal buffer.read_string, "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        assert_equal buffer.read_string, cert.to_blob
        assert_equal buffer.read_bignum, cert.key.private_key
        assert_equal 'foobar', buffer.read_string
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(cert, "foobar")
    end

    def test_add_ed25519_identity
      return unless Net::SSH::Authentication::ED25519Loader::LOADED
      ed25519 = Net::SSH::Authentication::ED25519::PrivKey.read(ED25519, nil)
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_IDENTITY, type
        assert_equal buffer.read_string, "ssh-ed25519"
        assert_equal buffer.read_string, ed25519.public_key.verify_key.to_bytes
        assert_equal buffer.read_string, ed25519.sign_key.keypair
        assert_equal 'foobar', buffer.read_string
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(ed25519, "foobar")
    end

    def test_add_ed25519_cert_identity
      return unless Net::SSH::Authentication::ED25519Loader::LOADED
      cert = make_cert(Net::SSH::Authentication::ED25519::PrivKey.read(ED25519, nil))
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_ADD_IDENTITY, type
        assert_equal buffer.read_string, "ssh-ed25519-cert-v01@openssh.com"
        assert_equal buffer.read_string, cert.to_blob
        assert_equal buffer.read_string, cert.key.public_key.verify_key.to_bytes
        assert_equal buffer.read_string, cert.key.sign_key.keypair
        assert_equal 'foobar', buffer.read_string
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.add_identity(cert, "foobar")
    end

    def test_add_identity_should_raise_error_on_failure
      socket.expect do |s,type,buffer|
        s.return(SSH_AGENT_FAILURE)
      end

      assert_raises(Net::SSH::Authentication::AgentError) do
        agent.add_identity(key, "foobar")
      end
    end

    def test_remove_identity
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_REMOVE_IDENTITY, type
        assert_equal buffer.read_string, key.to_blob
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.remove_identity(key)
    end

    def test_remove_identity_should_raise_error_on_failure
      socket.expect do |s,type,buffer|
        s.return(SSH_AGENT_FAILURE)
      end

      assert_raises(Net::SSH::Authentication::AgentError) do
        agent.remove_identity(key)
      end
    end

    def test_remove_all_identities
      socket.expect do |s,type,buffer|
        assert_equal SSH2_AGENT_REMOVE_ALL_IDENTITIES, type
        assert buffer.eof?

        s.return(SSH_AGENT_SUCCESS)
      end

      agent.remove_all_identities
    end

    def test_remove_all_identities_should_raise_error_on_failure
      socket.expect do |s,type,buffer|
        s.return(SSH_AGENT_FAILURE)
      end

      assert_raises(Net::SSH::Authentication::AgentError) do
        agent.remove_all_identities
      end
    end

    private

    def make_cert(key)
      cert = Net::SSH::Buffer.new(CERT).read_key
      cert.key = key
      cert.sign!(key)
    end

    class MockSocket
      def initialize
        @expectation = nil
        @buffer = Net::SSH::Buffer.new
      end

      def expect(&block)
        @expectation = block
      end

      def return(type, *args)
        data = Net::SSH::Buffer.from(*args)
        @buffer.append([data.length + 1, type, data.to_s].pack("NCA*"))
      end

      def send(data, flags)
        raise "got #{data.inspect} but no packet was expected" unless @expectation
        buffer = Net::SSH::Buffer.new(data)
        buffer.read_long # skip the length
        type = buffer.read_byte
        @expectation.call(self, type, buffer)
        @expectation = nil
      end

      def read(length)
        @buffer.read(length)
      end
    end

    def key
      @key ||= OpenSSL::PKey::RSA.new(512)
    end

    def socket
      @socket ||= MockSocket.new
    end

    def factory
      @factory ||= stub("socket factory", open: socket)
    end

    def agent(auto=:connect)
      @agent ||= begin
        agent = Net::SSH::Authentication::Agent.new
        agent.stubs(:unix_socket_class).returns(factory)
        agent.connect! if auto == :connect
        agent
      end
    end

    def agent_socket_factory
      @agent_socket_factory ||= -> {"/foo/bar.sock"}
    end
  end

end
