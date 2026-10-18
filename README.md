[![Gem Version](https://badge.fury.io/rb/net-ssh.svg)](https://badge.fury.io/rb/net-ssh)
[![Join the chat at https://gitter.im/net-ssh/net-ssh](https://badges.gitter.im/net-ssh/net-ssh.svg)](https://gitter.im/net-ssh/net-ssh?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build status](https://github.com/net-ssh/net-ssh/actions/workflows/ci.yml/badge.svg)](https://github.com/net-ssh/net-ssh/actions/workflows/ci.yml)
[![Coverage status](https://codecov.io/gh/net-ssh/net-ssh/branch/master/graph/badge.svg)](https://codecov.io/gh/net-ssh/net-ssh)
[![Backers on Open Collective](https://opencollective.com/net-ssh/backers/badge.svg)](#backers])
[![Sponsors on Open Collective](https://opencollective.com/net-ssh/sponsors/badge.svg)](#sponsors)

# Net::SSH 7.x

* Docs: http://net-ssh.github.io/net-ssh
* Issues: https://github.com/net-ssh/net-ssh/issues
* Codes: https://github.com/net-ssh/net-ssh
* Email: net-ssh@solutious.com

*As of v2.6.4, all gem releases are signed. See [INSTALL](#install).*

## DESCRIPTION:

Net::SSH is a pure-Ruby implementation of the SSH2 client protocol.
It allows you to write programs that invoke and interact with processes on remote servers, via SSH2.

## FEATURES:

* Execute processes on remote servers and capture their output
* Run multiple processes in parallel over a single SSH connection
* Support for SSH subsystems
* Forward local and remote ports via an SSH connection

## Supported Algorithms

Net::SSH only offers secure algorithms by default.
We strongly recommend that you install a server version that supports the latest algorithms.

Weak algorithms are still supported as opt-ins, so legacy servers such as embedded routers and old network gear stay reachable. To enable one, prefix it with `+` in the matching option, e.g. `encryption: '+aes256-cbc'`, `hmac: '+hmac-sha1-96'`, `kex: '+diffie-hellman-group1-sha1'`, `host_key: '+ssh-dss'`, or in ssh_config with `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms` and `PubkeyAcceptedAlgorithms` (e.g. `Ciphers +aes256-cbc`). Passing `append_all_supported_algorithms: true` appends every supported algorithm except the `none` cipher and MAC, which are only used when named explicitly (e.g. `encryption: '+none'`, `hmac: '+none'`).

### Host Keys

| Name                                     | Support                | Details  |
|------------------------------------------|------------------------|----------|
| ssh-ed25519                              | OK                     | Backed by Ruby OpenSSL raw Ed25519 APIs (`openssl >= 3.2.0`) |
| ssh-ed25519-cert-v01@openssh.com         | OK                     | Backed by Ruby OpenSSL raw Ed25519 APIs (`openssl >= 3.2.0`) |
| ecdsa-sha2-nistp521/384/256              | OK                     | [using weak elliptic curves](https://safecurves.cr.yp.to/) |
| ecdsa-sha2-nistp521/384/256-cert-v01@openssh.com | OK             | [using weak elliptic curves](https://safecurves.cr.yp.to/) |
| rsa-sha2-512                             | OK                     |          |
| rsa-sha2-256                             | OK                     |          |
| ssh-rsa                                  | Not offered by default | SHA-1 signatures, off by default as in OpenSSH 8.8; opt-in for legacy servers with `HostKeyAlgorithms +ssh-rsa` or `host_key: '+ssh-rsa'` |
| ssh-rsa-cert-v01@openssh.com             | Not offered by default | SHA-1 signatures; opt-in for legacy servers |
| ssh-rsa-cert-v00@openssh.com             | Deprecated             | not offered by default, warns when used and will be removed; net-ssh cannot parse v00 certificates, use ssh-rsa-cert-v01@openssh.com or a modern key type |
| ssh-dss                                  | Not offered by default | unsecure, off by default as in OpenSSH 7.0; opt-in for legacy servers |

RSA public key authentication likewise uses rsa-sha2-512 or rsa-sha2-256 by default; ssh-rsa and ssh-dss keys are only offered when enabled, e.g. with `PubkeyAcceptedAlgorithms +ssh-rsa` or `pubkey_algorithms: %w[+ssh-rsa]`.

### Key Exchange

| Name                                 | Support                | Details  |
|--------------------------------------|------------------------|----------|
| curve25519-sha256                    | OK                     | Backed by Ruby OpenSSL raw X25519 APIs (`openssl >= 3.2.0`) |
| curve25519-sha256@libssh.org         | OK                     | Backed by Ruby OpenSSL raw X25519 APIs (`openssl >= 3.2.0`) |
| ecdh-sha2-nistp521                   | OK                     | [using weak elliptic curves](https://safecurves.cr.yp.to/) |
| ecdh-sha2-nistp384                   | OK                     | [using weak elliptic curves](https://safecurves.cr.yp.to/) |
| ecdh-sha2-nistp256                   | OK                     | [using weak elliptic curves](https://safecurves.cr.yp.to/) |
| diffie-hellman-group-exchange-sha256 | OK                     |          |
| diffie-hellman-group14-sha256        | OK                     |          |
| diffie-hellman-group14-sha1          | Not offered by default | SHA-1, off by default as in OpenSSH 8.2; opt-in for legacy servers with `KexAlgorithms +diffie-hellman-group14-sha1` or `kex: '+diffie-hellman-group14-sha1'` |
| diffie-hellman-group-exchange-sha1   | Not offered by default | unsecure; opt-in for legacy servers |
| diffie-hellman-group1-sha1           | Not offered by default | unsecure; opt-in for legacy servers |

### Encryption algorithms (ciphers)

| Name                                    | Support                | Details  |
|-----------------------------------------|------------------------|----------|
| chacha20-poly1305@openssh.com           | OK                     | Backed by Ruby OpenSSL ChaCha20 and Poly1305 APIs (`openssl >= 3.2.0`) |
| aes256-ctr / aes192-ctr / aes128-ctr    | OK                     |          |
| aes256-gcm@openssh.com / aes128-gcm@openssh.com | OK              |          |
| aes256-cbc / aes192-cbc / aes128-cbc    | Not offered by default | unsecure; opt-in for legacy servers |
| rijndael-cbc@lysator.liu.se             | Not offered by default | unsecure; opt-in for legacy servers |
| blowfish-ctr blowfish-cbc               | Not offered by default | unsecure; opt-in for legacy servers |
| cast128-ctr cast128-cbc                 | Not offered by default | unsecure; opt-in for legacy servers |
| 3des-ctr 3des-cbc                       | Not offered by default | unsecure; opt-in for legacy servers |
| idea-cbc                                | Not offered by default | unsecure; opt-in for legacy servers |
| none                                    | Not offered by default | no encryption; only used when named explicitly, not added by `append_all_supported_algorithms` |

### Message Authentication Code algorithms

| Name                          | Support                | Details  |
|-------------------------------|------------------------|----------|
| hmac-sha2-512-etm@openssh.com | OK                     |          |
| hmac-sha2-256-etm@openssh.com | OK                     |          |
| hmac-sha1-etm@openssh.com     | OK                     | for backward compatibility |
| hmac-sha2-512                 | OK                     |          |
| hmac-sha2-256                 | OK                     |          |
| hmac-sha1                     | OK                     | for backward compatibility |
| hmac-sha2-512-96              | Not offered by default | removed from the specification; opt-in for legacy servers |
| hmac-sha2-256-96              | Not offered by default | removed from the specification; opt-in for legacy servers |
| hmac-sha1-96                  | Not offered by default | unsecure; opt-in for legacy servers |
| hmac-ripemd160 / hmac-ripemd160@openssh.com | Not offered by default | unsecure; opt-in for legacy servers |
| hmac-md5                      | Not offered by default | unsecure; opt-in for legacy servers |
| hmac-md5-96                   | Not offered by default | unsecure; opt-in for legacy servers |
| none                          | Not offered by default | no integrity protection; only used when named explicitly, not added by `append_all_supported_algorithms` |

## SYNOPSIS:

In a nutshell:

```ruby
require 'net/ssh'

Net::SSH.start('host', 'user', password: "password") do |ssh|

# capture all stderr and stdout output from a remote process
output = ssh.exec!("hostname")
puts output

# capture only stdout matching a particular pattern
stdout = ""
ssh.exec!("ls -l /home/jamis") do |channel, stream, data|
  stdout << data if stream == :stdout && /foo/.match(data)
end
puts stdout

# run multiple processes in parallel to completion
ssh.exec "sed ..."
ssh.exec "awk ..."
ssh.exec "rm -rf ..."
ssh.loop

# open a new channel and configure a minimal set of callbacks, then run
# the event loop until the channel finishes (closes)
channel = ssh.open_channel do |ch|
  ch.exec "/usr/local/bin/ruby /path/to/file.rb" do |ch, success|
    raise "could not execute command" unless success

    # "on_data" is called when the process writes something to stdout
    ch.on_data do |c, data|
      $stdout.print data
    end

    # "on_extended_data" is called when the process writes something to stderr
    ch.on_extended_data do |c, type, data|
      $stderr.print data
    end

    ch.on_close { puts "done!" }
  end
end

channel.wait

# forward connections on local port 1234 to port 80 of www.capify.org
ssh.forward.local(1234, "www.capify.org", 80)
ssh.loop { true }
end
```

See Net::SSH for more documentation, and links to further information.

## REQUIREMENTS:

Net::SSH requires Ruby 2.7 or newer and the Ruby `openssl` gem version `3.2.0` or newer.
The `openssl` gem uses the OpenSSL library Ruby is built against. You can verify the loaded gem and library with:

```sh
ruby -ropenssl -e 'puts OpenSSL::VERSION; puts OpenSSL::OPENSSL_VERSION'
```

If `openssl` cannot be required, rebuild Ruby with OpenSSL support or install the Ruby `openssl` gem separately.

Ed25519, curve25519-sha256, and chacha20-poly1305@openssh.com support also require an OpenSSL backend with Ed25519, X25519, ChaCha20, and Poly1305 enabled.

## INSTALL:

```sh
gem install net-ssh # might need sudo privileges
```

NOTE: If you are running on jruby on windows you need to install `jruby-pageant` manually
(gemspec doesn't allow for platform specific dependencies at gem installation time).

However, in order to be sure the code you're installing hasn't been tampered with,
it's recommended that you verify the [signature](http://docs.rubygems.org/read/chapter/21).
 To do this, you need to add my public key as a trusted certificate (you only need to do this once):

```sh
# Add the public key as a trusted certificate
# (You only need to do this once)
curl -O https://raw.githubusercontent.com/net-ssh/net-ssh/master/net-ssh-public_cert.pem
gem cert --add net-ssh-public_cert.pem
```

Then, when install the gem, do so with high security:

```sh
gem install net-ssh -P HighSecurity
```

If you don't add the public key, you'll see an error like "Couldn't verify data signature".
If you're still having trouble let me know and I'll give you a hand.

Ed25519 public key auth is backed by Ruby OpenSSL. The `bcrypt_pbkdf` gem is only needed when loading bcrypt-encrypted OpenSSH private keys.

```sh
gem install bcrypt_pbkdf
```

### FIDO/U2F security keys

`sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ssh-ed25519@openssh.com` keys work when held in `ssh-agent`.
Loading `sk-*` private key files from disk is not supported.

## RUBY SUPPORT

* See [net-ssh.gemspec](https://github.com/net-ssh/net-ssh/blob/master/net-ssh.gemspec) for current versions ruby requirements

## RUNNING TESTS

If you want to run the tests or use any of the Rake tasks, you'll need Mocha and
other dependencies listed in Gemfile

Run the test suite from the net-ssh directory with the following command:

```sh
bundle exec rake test
```

NOTE : you can run test on all ruby versions with docker :

```
docker-compose up --build
```

Run a single test file like this:

```sh
ruby -Ilib -Itest test/transport/test_server_version.rb
```

To run integration tests see [here](test/integration/README.md)

### BUILDING GEM

```sh
rake build
```

### GEM SIGNING (for maintainers)

If you have the net-ssh private signing key, you will be able to create signed release builds. Make sure the private key path matches the `signing_key` path set in `net-ssh.gemspec` and tell rake to sign the gem by setting the `NET_SSH_BUILDGEM_SIGNED` flag:

```sh
NET_SSH_BUILDGEM_SIGNED=true rake build
```

For time to time, the public certificate associated to the private key needs to be renewed. You can do this with the following command:

```sh
gem cert --build netssh@solutious.com --private-key path/2/net-ssh-private_key.pem
mv gem-public_cert.pem net-ssh-public_cert.pem
gem cert --add net-ssh-public_cert.pem
```

or `rake cert:update_public_when_expired`

## CONTRIBUTING

See [CONTRIBUTING.md](CONTRIBUTING.md), including how to add a changelog entry.

## Security contact information

See [SECURITY.md](SECURITY.md)

## CREDITS

### Contributors

This project exists thanks to all the people who contribute.

[![contributors](https://opencollective.com/net-ssh/contributors.svg?width=890&button=false)](graphs/contributors)

### Backers

Thank you to all our backers! 🙏 [Become a backer](https://opencollective.com/net-ssh#backer)

[![backers](https://opencollective.com/net-ssh/backers.svg?width=890)](https://opencollective.com/net-ssh#backers)

### Sponsors

Support this project by becoming a sponsor. Your logo will show up here with a link to your website. [Become a sponsor](https://opencollective.com/net-ssh#sponsor)

[![Sponsor](https://opencollective.com/net-ssh/sponsor/0/avatar.svg)](https://opencollective.com/net-ssh/sponsor/0/website)

[<img src="https://github.com/net-ssh/net-ssh/assets/52435/9690bf3e-34ea-4c52-8aea-1cc4cb5bcb6d" width="320">](https://ubicloud.com)


## LICENSE:

(The MIT License)

Copyright (c) 2008 Jamis Buck

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
