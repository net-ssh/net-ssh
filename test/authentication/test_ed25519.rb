unless ENV['NET_SSH_NO_ED25519']

  require_relative '../common'
  require 'net/ssh/authentication/ed25519_loader'
  require 'net/ssh/key_factory'
  require 'base64'

  module Authentication

    class TestED25519 < NetSSHTest
      def setup
        raise "No ED25519 set NET_SSH_NO_ED25519 to ignore this test" unless Net::SSH::Authentication::ED25519Loader::LOADED
      end

      def test_no_pwd_key
        pub = Net::SSH::Buffer.new(Base64.decode64(public_key_no_pwd.split(' ')[1]))
        _type = pub.read_string
        pub_data = pub.read_string
        priv = private_key_no_pwd

        pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
        priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv, nil)

        shared_secret = "Hello"
        signed = priv_key.ssh_do_sign(shared_secret)
        self.assert_equal(true,pub_key.ssh_do_verify(signed,shared_secret))
        self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
        self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_no_pwd)
        self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_no_pwd)
      end

      def test_pwd_key
        if defined?(JRUBY_VERSION)
          puts "Skipping password protected ED25519 for JRuby"
          return
        end
        pub = Net::SSH::Buffer.new(Base64.decode64(public_key_pwd.split(' ')[1]))
        _type = pub.read_string
        pub_data = pub.read_string
        priv = private_key_pwd

        pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
        priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv,'pwd')

        shared_secret = "Hello"
        signed = priv_key.ssh_do_sign(shared_secret)
        self.assert_equal(true,pub_key.ssh_do_verify(signed,shared_secret))
        self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
        self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_pwd)
        self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_pwd)
      end

      def test_pwd_key_should_ask
        pub = Net::SSH::Buffer.new(Base64.decode64(public_key_pwd.split(' ')[1]))
        _type = pub.read_string
        pub_data = pub.read_string
        priv = private_key_pwd

        prompt = OpenStruct.new
        def prompt.start(opts)
          prompter = OpenStruct.new
          def prompter.ask(*opts)
            return "pwd"
          end
          prompter
        end

        pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
        priv_key = Net::SSH::KeyFactory.load_data_private_key(priv, nil, true, "", prompt)

        shared_secret = "Hello"
        signed = priv_key.ssh_do_sign(shared_secret)
        self.assert_equal(true,pub_key.ssh_do_verify(signed,shared_secret))
        self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
        self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_pwd)
        self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_pwd)
      end

      def private_key_pwd
        @pwd_key = <<-EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABBxwCvr3V
/8pWhC/xvTnGJhAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAICaHkFaGXqYhUVFc
aZ10TPUbkIvmaFXwYRoOS5qE8MciAAAAsNUAhbNQKwNcOr0eNq3nhtjoyeVyH8hRrpWsiY
46vPiECi6R6OdYGSd7W3fdzUDeyOYCY9ZVIjAzENG+9FsygYzMi6XCuw00OuDFLUp4fL4K
i/coUIVqouB4TPQAmsCVXiIRVTWQtRG0kWfFaV3qRt/bc22ZCvCT6ZZ1UmtulqqfUhSlKM
oPcTikV1iWH5Xc+GxRFRRGTN/6HvBf0AKDB1kMXlDhGnBnHGeNH1pk44xG
-----END OPENSSH PRIVATE KEY-----
      EOF
      end

      def public_key_pwd
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaHkFaGXqYhUVFcaZ10TPUbkIvmaFXwYRoOS5qE8Mci vagrant@vagrant-ubuntu-trusty-64'
      end

      def key_fingerprint_md5_pwd
        'c8:89:92:60:12:1b:01:5e:ca:58:55:68:7e:5e:1a:f1'
      end

      def key_fingerprint_sha256_pwd
        'SHA256:Uz5Qk/fB+f8Bu7FTxNcDh7+atpB29Q3tBBJX/gnUfGw'
      end

      def private_key_no_pwd
        @anonymous_key = <<-EOF
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQAAAKjlHzLo5R8y
6AAAAAtzc2gtZWQyNTUxOQAAACAwdjQYeBiTz1DdZFzzLvG+t913L+eVqCgtzpAYxQG8yQ
AAAEBPrD+n4901Y+NYJ2sry+EWRdltGFhMISvp91TywJ//mTB2NBh4GJPPUN1kXPMu8b63
3Xcv55WoKC3OkBjFAbzJAAAAIHZhZ3JhbnRAdmFncmFudC11YnVudHUtdHJ1c3R5LTY0AQ
IDBAU=
-----END OPENSSH PRIVATE KEY-----
      EOF
      end

      def public_key_no_pwd
        'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB2NBh4GJPPUN1kXPMu8b633Xcv55WoKC3OkBjFAbzJ vagrant@vagrant-ubuntu-trusty-64'
      end

      def key_fingerprint_md5_no_pwd
        '2f:7f:97:21:76:a4:0f:38:c4:fe:d8:b4:6a:39:72:30'
      end

      def key_fingerprint_sha256_no_pwd
        'SHA256:u6mXnY8P1b0FODGp8mckqOB33u8+jvkSCtJbD5Q9klg'
      end
    end

  end

end
