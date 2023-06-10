module Net::SSH::Transport
  module OpenSSLCipherExtensions 
    def implicit_mac?
      false
    end
  end
end