### Development notes

## Building/running ssh server in debug mode

clone the openssh server from `https://github.com/openssh/openssh-portable`

```sh
brew install openssl
/usr/local/Cellar/openssl@3/3.1.0/bin/openssl

autoreconf
./configure --with-ssl-dir=/usr/local/Cellar/openssl@3/3.1.0/ --with-audit=debug --enable-debug CPPFLAGS="-DDEBUG -DPACKET_DEBUG" CFLAGS="-g -O0"
make
```

To run server in debug mode:
```sh
echo '#' > /tmp/sshd_config
ssh-keygen -t rsa -f /tmp/ssh_host_rsa_key
# /Users/boga/Work/OSS/NetSSH/openssh-portable/sshd -p 2222 -D -d -d -d -e -f /tmp/sshd_config
/Users/boga/Work/OSS/NetSSH/openssh-portable/sshd -p 2222 -D -d -d -d -e -f /tmp/sshd_config -h /tmp/ssh_host_rsa_key

```
