gem 'rbnacl', '>= 3.2.0', '< 5.0'
gem 'bcrypt_pbkdf', '~> 1.0' unless RUBY_PLATFORM == "java"

begin
  require 'rbnacl/libsodium'
rescue LoadError # rubocop:disable Lint/HandleExceptions
end

require 'rbnacl'
require 'rbnacl/signatures/ed25519/verify_key'
require 'rbnacl/signatures/ed25519/signing_key'

require 'rbnacl/hash'

require 'base64'

require 'net/ssh/transport/cipher_factory'
require 'bcrypt_pbkdf' unless RUBY_PLATFORM == "java"

module Net; module SSH; module Authentication
module ED25519
  class SigningKeyFromFile < RbNaCl::Signatures::Ed25519::SigningKey
    def initialize(pk,sk)
      @signing_key = sk
      @verify_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(pk)
    end
  end

  class PubKey
    attr_reader :verify_key

    def initialize(data)
      @verify_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(data)
    end

    def self.read_keyblob(buffer)
      PubKey.new(buffer.read_string)
    end

    def to_blob
      Net::SSH::Buffer.from(:mstring,"ssh-ed25519",:string,@verify_key.to_bytes).to_s
    end

    def ssh_type
      "ssh-ed25519"
    end

    def ssh_signature_type
      ssh_type
    end

    def ssh_do_verify(sig,data)
      @verify_key.verify(sig,data)
    end

    def to_pem
      # TODO this is not pem
      ssh_type + Base64.encode64(@verify_key.to_bytes)
    end

    def fingerprint
      @fingerprint ||= OpenSSL::Digest::MD5.hexdigest(to_blob).scan(/../).join(":")
    end
  end

  class PrivKey
    CipherFactory = Net::SSH::Transport::CipherFactory

    MBEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    MEND = "-----END OPENSSH PRIVATE KEY-----\n"
    MAGIC = "openssh-key-v1"

    attr_reader :sign_key

    def initialize(datafull,password)
      raise ArgumentError.new("Expected #{MBEGIN} at start of private key") unless datafull.start_with?(MBEGIN)
      raise ArgumentError.new("Expected #{MEND} at end of private key") unless datafull.end_with?(MEND)
      datab64 = datafull[MBEGIN.size ... -MEND.size]
      data = Base64.decode64(datab64)
      raise ArgumentError.new("Expected #{MAGIC} at start of decoded private key") unless data.start_with?(MAGIC)
      buffer = Net::SSH::Buffer.new(data[MAGIC.size+1 .. -1])

      ciphername = buffer.read_string
      raise ArgumentError.new("#{ciphername} in private key is not supported") unless
        CipherFactory.supported?(ciphername)

      kdfname = buffer.read_string
      raise ArgumentError.new("Expected #{kdfname} to be or none or bcrypt") unless %w(none bcrypt).include?(kdfname)

      kdfopts = Net::SSH::Buffer.new(buffer.read_string)
      num_keys = buffer.read_long
      raise ArgumentError.new("Only 1 key is supported in ssh keys #{num_keys} was in private key") unless num_keys == 1
      _pubkey = buffer.read_string

      len = buffer.read_long

      keylen, blocksize, ivlen = CipherFactory.get_lengths(ciphername, iv_len: true)
      raise ArgumentError.new("Private key len:#{len} is not a multiple of #{blocksize}") if
        ((len < blocksize) || ((blocksize > 0) && (len % blocksize) != 0))

      if kdfname == 'bcrypt'
        salt = kdfopts.read_string
        rounds = kdfopts.read_long

        raise "BCryptPbkdf is not implemented for jruby" if RUBY_PLATFORM == "java"
        key = BCryptPbkdf::key(password, salt, keylen + ivlen, rounds)
      else
        key = '\x00' * (keylen + ivlen)
      end

      cipher = CipherFactory.get(ciphername, key: key[0...keylen], iv:key[keylen...keylen+ivlen], decrypt: true)

      decoded = cipher.update(buffer.remainder_as_buffer.to_s)
      decoded << cipher.final

      decoded = Net::SSH::Buffer.new(decoded)
      check1 = decoded.read_long
      check2 = decoded.read_long

      raise ArgumentError, "Decrypt failed on private key" if (check1 != check2)

      _type_name = decoded.read_string
      pk = decoded.read_string
      sk = decoded.read_string
      _comment = decoded.read_string

      @pk = pk
      @sign_key = SigningKeyFromFile.new(pk,sk)
    end

    def to_blob
      public_key.to_blob
    end

    def ssh_type
      "ssh-ed25519"
    end

    def ssh_signature_type
      ssh_type
    end

    def public_key
      PubKey.new(@pk)
    end

    def ssh_do_sign(data)
      @sign_key.sign(data)
    end

    def self.read(data,password)
      self.new(data,password)
    end

    def self.read_keyblob(buffer)
      ED25519::PubKey.read_keyblob(buffer)
    end
  end
end
end; end; end
