# frozen_string_literal: true

module Net::SSH::Transport
  # we add those mehtods to OpenSSL::Chipher instances
  module OpenSSLCipherExtensions
    def implicit_mac?
      false
    end
  end
end
