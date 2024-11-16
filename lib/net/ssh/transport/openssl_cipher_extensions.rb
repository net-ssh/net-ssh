module Net::SSH::Transport
  # we add those mehtods to OpenSSL::Chipher instances
  module OpenSSLCipherExtensions
    def implicit_mac?
      false
    end
  end
end
