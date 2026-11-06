require_relative '../common'
require 'net/ssh/proxy/https'
require 'socket'

module NetSSH
  class TestProxyHTTPS < NetSSHTest
    KEY = OpenSSL::PKey::RSA.new(2048)

    def test_default_ssl_context_verifies_peer_and_hostname
      context = Net::SSH::Proxy::HTTPS.new('localhost', 443).instance_variable_get(:@ssl_context)

      assert_equal OpenSSL::SSL::VERIFY_PEER, context.verify_mode
      assert context.verify_hostname
    end

    def test_default_ssl_context_refuses_an_untrusted_certificate
      with_tls_proxy(certificate('localhost')) do |port, requests|
        assert_raises(OpenSSL::SSL::SSLError) { open_proxy('localhost', port) }
        assert_empty requests
      end
    end

    def test_trusted_certificate_for_another_host_is_refused_and_closed
      cert = certificate('other.test')
      with_tls_proxy(cert) do |port, requests|
        assert_raises(OpenSSL::SSL::SSLError) { open_proxy('localhost', port, ssl_context: trusting(cert)) }
        assert_empty requests
      end
    end

    def test_trusted_certificate_for_the_proxy_host_connects_with_sni
      cert = certificate('localhost')
      with_tls_proxy(cert) do |port, requests, server_names|
        open_proxy('localhost', port, ssl_context: trusting(cert)).close
        assert_includes requests.join, "Proxy-Authorization: Basic"
        assert_equal ['localhost'], server_names
      end
    end

    def test_proxy_addressed_by_ip_is_verified_without_sni
      cert = certificate('127.0.0.1', san: 'IP:127.0.0.1')
      with_tls_proxy(cert) do |port, requests, server_names|
        open_proxy('127.0.0.1', port, ssl_context: trusting(cert)).close
        refute_empty requests
        assert_empty server_names
      end
    end

    def test_context_without_verification_skips_certificate_and_hostname_checks
      none = OpenSSL::SSL::SSLContext.new
      none.verify_mode = OpenSSL::SSL::VERIFY_NONE

      [none, OpenSSL::SSL::SSLContext.new].each do |context|
        with_tls_proxy(certificate('other.test')) do |port, requests|
          open_proxy('localhost', port, ssl_context: context).close
          refute_empty requests
        end
      end
    end

    private

    def open_proxy(host, port, options = {})
      proxy = Net::SSH::Proxy::HTTPS.new(host, port, { user: 'user', password: 'secret' }.merge(options))
      proxy.open('target.test', 22, timeout: 5)
    end

    def trusting(cert)
      OpenSSL::SSL::SSLContext.new.tap do |context|
        context.verify_mode = OpenSSL::SSL::VERIFY_PEER
        context.cert_store = OpenSSL::X509::Store.new.tap { |store| store.add_cert(cert) }
      end
    end

    def certificate(name, san: "DNS:#{name}")
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = rand(1 << 32)
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=#{name}")
      cert.public_key = KEY.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 60
      factory = OpenSSL::X509::ExtensionFactory.new(cert, cert)
      cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
      cert.add_extension(factory.create_extension('subjectAltName', san))
      cert.sign(KEY, OpenSSL::Digest.new('SHA256'))
    end

    # Joining the server thread also proves a refused client closed its socket,
    # since the server otherwise blocks waiting for the CONNECT request.
    def with_tls_proxy(cert)
      requests = []
      server_names = []
      context = OpenSSL::SSL::SSLContext.new
      context.cert = cert
      context.key = KEY
      context.servername_cb = proc do |_socket, name|
        server_names << name
        nil
      end
      tcp_server = TCPServer.new('127.0.0.1', 0)
      server = serve(OpenSSL::SSL::SSLServer.new(tcp_server, context), requests)

      yield tcp_server.addr[1], requests, server_names

      assert server.join(5), 'the proxy connection was left open'
    ensure
      server&.kill
      tcp_server&.close
    end

    def serve(tls_server, requests)
      Thread.new do
        socket = tls_server.accept
        while (line = socket.gets) && line != "\r\n"
          requests << line
        end
        socket.write("HTTP/1.1 200 OK\r\n\r\n") unless requests.empty?
        socket.close
      rescue OpenSSL::SSL::SSLError, SystemCallError, IOError
        nil
      end
    end
  end
end
