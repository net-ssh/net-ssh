require_relative '../common'
require 'net/ssh/proxy/https'

module NetSSH
  class TestProxyHTTPS < NetSSHTest
    # Regression for the HTTPS proxy accepting any TLS certificate because the
    # default SSL context was a bare OpenSSL::SSL::SSLContext (VERIFY_NONE).
    def test_default_ssl_context_verifies_peer
      proxy = Net::SSH::Proxy::HTTPS.new('proxy.example.com', 443)
      context = proxy.instance_variable_get(:@ssl_context)

      refute_nil context.verify_mode
      assert_equal OpenSSL::SSL::VERIFY_PEER, context.verify_mode
    end

    def test_supplied_ssl_context_is_left_untouched
      supplied = OpenSSL::SSL::SSLContext.new
      supplied.verify_mode = OpenSSL::SSL::VERIFY_NONE

      proxy = Net::SSH::Proxy::HTTPS.new('proxy.example.com', 443, ssl_context: supplied)

      assert_same supplied, proxy.instance_variable_get(:@ssl_context)
      assert_equal OpenSSL::SSL::VERIFY_NONE,
                   proxy.instance_variable_get(:@ssl_context).verify_mode
    end
  end
end
