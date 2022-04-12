ARG RUBY_VERSION=3.1
FROM ruby:${RUBY_VERSION}

ENV INSTALL_PATH="/netssh"

WORKDIR $INSTALL_PATH

COPY Gemfile net-ssh.gemspec $INSTALL_PATH/

COPY lib/net/ssh/version.rb $INSTALL_PATH/lib/net/ssh/version.rb

RUN gem install bundler && bundle install

COPY . $INSTALL_PATH/

CMD rake test
