ARG RUBY_VERSION=3.1
FROM ruby:${RUBY_VERSION}

ARG BUNDLERV=

# Ruby 2.6 to 3.0 images are built on Debian bullseye, which only archive.debian.org still serves.
RUN if grep -q bullseye /etc/os-release; then sed -i 's|deb.debian.org|archive.debian.org|; s|security.debian.org|archive.debian.org|' /etc/apt/sources.list; fi

RUN apt update && apt install -y openssh-server sudo netcat-openbsd \
  && useradd --create-home --shell '/bin/bash' --comment 'NetSSH' 'net_ssh_1' \
  && useradd --create-home --shell '/bin/bash' --comment 'NetSSH' 'net_ssh_2' \
  && echo net_ssh_1:foopwd | chpasswd \
  && echo net_ssh_2:foo2pwd | chpasswd \
  && mkdir -p /home/net_ssh_1/.ssh \
  && mkdir -p /home/net_ssh_2/.ssh \
  && echo "net_ssh_1 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
  && echo "net_ssh_2 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
  && ssh-keygen -f /etc/ssh/users_ca -N ''

ENV INSTALL_PATH="/netssh"

WORKDIR $INSTALL_PATH

COPY Gemfile net-ssh.gemspec $INSTALL_PATH/

COPY lib/net/ssh/version.rb $INSTALL_PATH/lib/net/ssh/version.rb

RUN gem install bundler ${BUNDLERV}  && bundle install

COPY . $INSTALL_PATH/

CMD service ssh start && rake test && NET_SSH_NO_ED25519=1 rake test
