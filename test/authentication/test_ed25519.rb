require_relative '../common'
require 'net/ssh/authentication/ed25519_loader'
require 'net/ssh/key_factory'
require 'base64'

module Authentication
  class TestED25519 < NetSSHTest
    def setup
      skip "Ed25519 is not available" unless Net::SSH::Authentication::ED25519Loader::LOADED
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
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_no_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_no_pwd)
    end

    def test_no_pwd_key_with_newlines
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key_no_pwd.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string
      priv = private_key_no_pwd_with_newlines

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv, nil)

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
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
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(priv, 'pwd')

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_pwd)
    end

    def test_aes128_gcm_pwd_key
      assert_pwd_key_matches_public_key(private_key_aes128_gcm_pwd, public_key_aes128_gcm_pwd)
    end

    def test_aes256_gcm_pwd_key
      assert_pwd_key_matches_public_key(private_key_aes256_gcm_pwd, public_key_aes256_gcm_pwd)
    end

    def test_chacha20_poly1305_pwd_key
      skip "chacha20-poly1305@openssh.com is not available" unless
        Net::SSH::Transport::ChaCha20Poly1305CipherLoader::LOADED

      assert_pwd_key_matches_public_key(private_key_chacha20_poly1305_pwd, public_key_chacha20_poly1305_pwd)
    end

    def test_aead_pwd_key_with_wrong_password_is_retryable
      skip "chacha20-poly1305@openssh.com is not available" unless
        Net::SSH::Transport::ChaCha20Poly1305CipherLoader::LOADED

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_chacha20_poly1305_pwd, 'wrong')
      end

      assert error.encrypted_key?
    end

    def test_no_pwd_key_does_not_require_bcrypt_pbkdf
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:require_bcrypt_pbkdf).never

      Net::SSH::Authentication::ED25519::PrivKey.read(private_key_no_pwd, nil)
    end

    def test_pwd_key_without_bcrypt_pbkdf_raises_targeted_decrypt_error
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:require_bcrypt_pbkdf)
                                                                .raises(LoadError)

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_pwd, 'pwd')
      end

      refute error.encrypted_key?
      assert_match(/bcrypt_pbkdf is required/, error.message)
    end

    def test_pwd_key_without_bcrypt_pbkdf_does_not_prompt_for_more_passphrases
      Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader.expects(:require_bcrypt_pbkdf)
                                                                .raises(LoadError)
      prompt = mock('prompt')
      prompt.expects(:start).never

      error = assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::KeyFactory.load_data_private_key(private_key_pwd, nil, true, '', prompt)
      end

      refute error.encrypted_key?
      assert_match(/bcrypt_pbkdf is required/, error.message)
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
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
      self.assert_equal(pub_key.fingerprint, key_fingerprint_md5_pwd)
      self.assert_equal(pub_key.fingerprint('sha256'), key_fingerprint_sha256_pwd)
    end

    def test_pwd_key_blank
      self.assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_no_rounds, '')
      end
    end

    def test_priv_key_no_rounds_should_raise
      self.assert_raises(Net::SSH::Authentication::ED25519::OpenSSHPrivateKeyLoader::DecryptError) do
        Net::SSH::Authentication::ED25519::PrivKey.read(private_key_no_rounds, 'pwd')
      end
    end

    def assert_pwd_key_matches_public_key(private_key, public_key)
      pub = Net::SSH::Buffer.new(Base64.decode64(public_key.split(' ')[1]))
      _type = pub.read_string
      pub_data = pub.read_string

      pub_key = Net::SSH::Authentication::ED25519::PubKey.new(pub_data)
      priv_key = Net::SSH::Authentication::ED25519::PrivKey.read(private_key, 'pwd')

      shared_secret = "Hello"
      signed = priv_key.ssh_do_sign(shared_secret)
      self.assert_equal(true, pub_key.ssh_do_verify(signed, shared_secret))
      self.assert_equal(priv_key.public_key.fingerprint, pub_key.fingerprint)
    end

    def private_key_pwd
      @pwd_key = <<~EOF
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

    def private_key_aes128_gcm_pwd
      <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAAFmFlczEyOC1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA
        AAGAAAABD7fJqyikc+oGFRyPNFeYW+AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA
        ICjavy2Z6HRO1gnczDXj/li91GQ/yyd2UTk4cpHN3XotAAAAoHdc7A78wsOAwOzeuxuC5G
        VeHz6StESIIrc/u0a2k1H4tHsAfVK1QphPTuhigypuko1cxbAjWDJ3l2m4TnGMltYNixBt
        rcmDaMxhAVu2W1XQds7sfUw0BqbgkQDjAH5LQzv/897+QMdOziGWfR6jC+VBo+Gzgnbv4a
        xivRbVdrUjhon9jdg2HiUZDLE14FOegWCSrc76UqS9gaScVQEc3WObuoxFZP3OTYMsg8FV
        MnJJ
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_aes256_gcm_pwd
      <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAAFmFlczI1Ni1nY21Ab3BlbnNzaC5jb20AAAAGYmNyeXB0AA
        AAGAAAABAIYrZ1Iy7viUsL4JBEZBUQAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAA
        IOEnJoGcYaqIKnB8qUdFbCxewkX78jQop1KRb4F6xX/tAAAAkAue/lM/EQ+M8fbjG+ab3x
        hrWZuaRvEbnzpe2+oPCxyGklVIC5pkNgDAfm4wGE+e81FGV0b323yMNbFZBWp61g+QLPEO
        kK0U0L/oK8pbJc4sIu2X3dOnCsmgptbi7L/L1ABzbaD2nKKJ4JV1MDwGawKOryD4XAcVCG
        4xrbZV1uR5iiq7wNQ3e6MVDbMlR7657aA7IBJ6zTlN8Ih9W6gb21w=
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_chacha20_poly1305_pwd
      <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAAHWNoYWNoYTIwLXBvbHkxMzA1QG9wZW5zc2guY29tAAAABm
        JjcnlwdAAAABgAAAAQF0S3Ou3bJxwGdfaAdynA5gAAABgAAAABAAAAMwAAAAtzc2gtZWQy
        NTUxOQAAACBGlIfrlzFWtRPdTGzaIT4D84KuBCzLbukafbUIlslwjAAAAJALFmJsY67YcH
        B01Fy7YoHRKUNL/82vC3uxTkhmqHhbDPeLdCdIyvdFpyKp5lrGtIx5K44PKOEU98hDL+Nk
        QGM5HAurbKxg20ZaiYIaF/lmmXSIoEXDJjmxMZhf5c7UkqozXl4puRs6oxQChcg9Rzj9LO
        b6XVrFTWbbgxAwzFkAs5qF0aPI5nsKgTdQX17M4afu86UIj6vPaHF4oMypei5N
        -----END OPENSSH PRIVATE KEY-----
      EOF
    end

    def private_key_no_rounds
      @private_key_no_rounds = <<~EOF
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAA
        ABBxwCvr3V/8pWhC/xvTnGJhAAAAAAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5
        AAAAICaHkFaGXqYhUVFcaZ10TPUbkIvmaFXwYRoOS5qE8MciAAAAsNUAhbNQ
        KwNcOr0eNq3nhtjoyeVyH8hRrpWsiY46vPiECi6R6OdYGSd7W3fdzUDeyOYC
        Y9ZVIjAzENG+9FsygYzMi6XCuw00OuDFLUp4fL4Ki/coUIVqouB4TPQAmsCV
        XiIRVTWQtRG0kWfFaV3qRt/bc22ZCvCT6ZZ1UmtulqqfUhSlKMoPcTikV1iW
        H5Xc+GxRFRRGTN/6HvBf0AKDB1kMXlDhGnBnHGeNH1pk44xG
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

    def public_key_aes128_gcm_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjavy2Z6HRO1gnczDXj/li91GQ/yyd2UTk4cpHN3Xot aes128gcm-test'
    end

    def public_key_aes256_gcm_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOEnJoGcYaqIKnB8qUdFbCxewkX78jQop1KRb4F6xX/t aesgcm-test'
    end

    def public_key_chacha20_poly1305_pwd
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEaUh+uXMVa1E91MbNohPgPzgq4ELMtu6Rp9tQiWyXCM chacha-test'
    end

    def private_key_no_pwd
      @anonymous_key = <<~EOF
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

    def private_key_no_pwd_with_newlines
      @anonymous_key = <<~EOF
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
