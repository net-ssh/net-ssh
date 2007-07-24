require 'base64'
require 'net/ssh/transport/openssl'

module Net; module SSH

  # A factory class for returning new Key classes.
  class KeyFactory
    MAP = {
      "dh"  => OpenSSL::PKey::DH,
      "rsa" => OpenSSL::PKey::RSA,
      "dsa" => OpenSSL::PKey::DSA
    }

    # Return a new instance of the key factory for the given name.
    def self.get(name)
      MAP.fetch(name).new
    end

    # Loads a private key from a file. It will correctly determine
    # whether the file describes an RSA or DSA key, and will load it
    # appropriately. The new key is returned. If the key itself is
    # encrypted (requiring a passphrase to use), the user will be
    # prompted to enter their password. 
    def load_private_key(filename)
      file = File.read(filename)

      if file.match(/-----BEGIN DSA PRIVATE KEY-----/)
        key_type = OpenSSL::PKey::DSA
      elsif file.match(/-----BEGIN RSA PRIVATE KEY-----/)
        key_type = OpenSSL::PKey::RSA
      elsif file.match(/-----BEGIN (.*) PRIVATE KEY-----/)
        raise OpenSSL::PKey::PKeyError, "not a supported key type '#{$1}'"
      else
        raise OpenSSL::PKey::PKeyError, "not a private key (#{filename})"
      end

      encrypted_key = file.match(/ENCRYPTED/)
      password = encrypted_key ? 'nil' : nil
      tries = 0

      begin
        return key_type.new(file, password)
      rescue OpenSSL::PKey::RSAError, OpenSSL::PKey::DSAError => e
        if encrypted_key && @prompter
          tries += 1
          if tries <= 3
            password = @prompter.password(
              "Enter password for #{filename}: ")
            retry
          else
            raise
          end
        else
          raise
        end
      end
    end

    # Loads a public key from a file. It will correctly determine whether
    # the file describes an RSA or DSA key, and will load it
    # appropriately. The new public key is returned.
    def load_public_key(filename)
      data = File.read(filename)
      type, blob = data.split(/ /)

      blob = Base64.decode64(blob)
      reader = Net::SSH::Buffer.new(blob)
      reader.read_key or raise OpenSSL::PKey::PKeyError, "not a public key #{filename.inspect}"
    end

  end

end; end
