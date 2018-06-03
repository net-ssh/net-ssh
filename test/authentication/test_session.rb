require_relative '../common'
require 'net/ssh/authentication/session'

module Authentication

  class TestSession < NetSSHTest
    include Net::SSH::Transport::Constants
    include Net::SSH::Authentication::Constants

    def test_constructor_should_set_defaults
      assert_equal %w[none publickey password keyboard-interactive], session.auth_methods
      assert_equal session.auth_methods, session.allowed_auth_methods
    end

    def test_authenticate_should_continue_if_method_disallowed
      transport.expect do |t, packet|
        assert_equal SERVICE_REQUEST, packet.type
        assert_equal "ssh-userauth", packet.read_string
        t.return(SERVICE_ACCEPT)
      end

      Net::SSH::Authentication::Methods::Publickey.any_instance.expects(:authenticate).with("next service", "username", "password").raises(Net::SSH::Authentication::DisallowedMethod)
      Net::SSH::Authentication::Methods::Password.any_instance.expects(:authenticate).with("next service", "username", "password").returns(true)
      Net::SSH::Authentication::Methods::None.any_instance.expects(:authenticate).with("next service", "username", "password").returns(false)

      assert session.authenticate("next service", "username", "password")
    end

    def test_authenticate_should_raise_error_if_service_request_fails
      transport.expect do |t, packet|
        assert_equal SERVICE_REQUEST, packet.type
        assert_equal "ssh-userauth", packet.read_string
        t.return(255)
      end

      assert_raises(Net::SSH::Exception) { session.authenticate("next service", "username", "password") }
    end

    def test_authenticate_should_return_false_if_all_auth_methods_fail
      transport.expect do |t, packet|
        assert_equal SERVICE_REQUEST, packet.type
        assert_equal "ssh-userauth", packet.read_string
        t.return(SERVICE_ACCEPT)
      end

      Net::SSH::Authentication::Methods::Publickey.any_instance.expects(:authenticate).with("next service", "username", "password").returns(false)
      Net::SSH::Authentication::Methods::Password.any_instance.expects(:authenticate).with("next service", "username", "password").returns(false)
      Net::SSH::Authentication::Methods::KeyboardInteractive.any_instance.expects(:authenticate).with("next service", "username", "password").returns(false)
      Net::SSH::Authentication::Methods::None.any_instance.expects(:authenticate).with("next service", "username", "password").returns(false)

      assert_equal false, session.authenticate("next service", "username", "password")
    end

    def test_next_message_should_silently_handle_USERAUTH_BANNER_packets
      transport.return(USERAUTH_BANNER, :string, "Howdy, folks!")
      transport.return(SERVICE_ACCEPT)
      assert_equal SERVICE_ACCEPT, session.next_message.type
    end

    def test_next_message_should_understand_USERAUTH_FAILURE
      transport.return(USERAUTH_FAILURE, :string, "a,b,c", :bool, false)
      packet = session.next_message
      assert_equal USERAUTH_FAILURE, packet.type
      assert_equal %w[a b c], session.allowed_auth_methods
    end

    (60..79).each do |type|
      define_method("test_next_message_should_return_packets_of_type_#{type}") do
        transport.return(type)
        assert_equal type, session.next_message.type
      end
    end

    def test_next_message_should_understand_USERAUTH_SUCCESS
      transport.return(USERAUTH_SUCCESS)
      assert !transport.hints[:authenticated]
      assert_equal USERAUTH_SUCCESS, session.next_message.type
      assert transport.hints[:authenticated]
    end

    def test_next_message_should_raise_error_on_unrecognized_packet_types
      transport.return(1)
      assert_raises(Net::SSH::Exception) { session.next_message }
    end

    def test_expect_message_should_raise_exception_if_next_packet_is_not_expected_type
      transport.return(SERVICE_ACCEPT)
      assert_raises(Net::SSH::Exception) { session.expect_message(USERAUTH_BANNER) }
    end

    def test_expect_message_should_return_packet_if_next_packet_is_expected_type
      transport.return(SERVICE_ACCEPT)
      assert_equal SERVICE_ACCEPT, session.expect_message(SERVICE_ACCEPT).type
    end

    def test_uses_some_default_keys_if_none_are_provided
      File.stubs(:file?).returns(false)

      file_on_filesystem("~/.ssh/id_rsa", default_private_key)

      transport.expect do |t, packet|
        assert_equal SERVICE_REQUEST, packet.type
        assert_equal "ssh-userauth", packet.read_string
        t.return(SERVICE_ACCEPT)
      end

      transport.expect do |t, packet|
        assert_none_request packet
        t.return(USERAUTH_FAILURE, :string, "publickey")
      end

      transport.expect do |t, packet|
        assert_public_key_request default_public_key, packet
        t.return(USERAUTH_FAILURE, :string, "publickey")
      end

      session.authenticate("next service", "username")
    end

    def test_does_not_use_default_keys_if_keys_are_present_in_options
      File.stubs(:file?).returns(false)

      file_on_filesystem("~/.ssh/id_rsa", default_private_key)
      file_on_filesystem("custom_rsa_id", custom_private_key)

      transport.expect do |t, packet|
        assert_equal SERVICE_REQUEST, packet.type
        assert_equal "ssh-userauth", packet.read_string
        t.return(SERVICE_ACCEPT)
      end

      transport.expect do |t, packet|
        assert_none_request packet
        t.return(USERAUTH_FAILURE, :string, "publickey")
      end

      transport.expect do |t, packet|
        assert_public_key_request custom_public_key, packet
        t.return(USERAUTH_FAILURE, :string, "publickey")
      end

      session(keys: "custom_rsa_id").authenticate("next service", "username")
    end

    def test_does_not_use_default_keys_if_key_data_are_present_in_options
      File.stubs(:file?).returns(false)

      file_on_filesystem("~/.ssh/id_rsa", default_private_key)

      transport.expect do |t, packet|
        assert_equal SERVICE_REQUEST, packet.type
        assert_equal "ssh-userauth", packet.read_string
        t.return(SERVICE_ACCEPT)
      end

      transport.expect do |t, packet|
        assert_none_request packet
        t.return(USERAUTH_FAILURE, :string, "publickey")
      end

      transport.expect do |t, packet|
        assert_public_key_request custom_public_key, packet
        t.return(USERAUTH_FAILURE, :string, "publickey")
      end

      session(key_data: custom_private_key).authenticate("next service", "username")
    end

    private

    def session(options={})
      @session ||= Net::SSH::Authentication::Session.new(transport(options), options)
    end

    def transport(options={})
      @transport ||= MockTransport.new(options)
    end

    def assert_none_request(packet)
      assert_equal "username", packet.read_string
      assert_equal "next service", packet.read_string
      assert_equal "none", packet.read_string
    end

    def assert_public_key_request(public_key, packet)
      assert_equal "username", packet.read_string
      assert_equal "next service", packet.read_string
      assert_equal "publickey", packet.read_string
      assert_equal false, packet.read_bool
      assert_equal "ssh-rsa", packet.read_string
      key_in_packet = Net::SSH::Buffer.new(packet.read_string).read_key
      assert_equal public_key, key_in_packet.to_pem
    end

    def file_on_filesystem(name, contents)
      path = File.expand_path(name)
      File.stubs(:read).with(path).returns(contents)
      File.stubs(:file?).with(path).returns(true)
      File.stubs(:readable?).with(path).returns(true)
    end

    def custom_private_key
      <<-EOF
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3id5gZ6bglJth
yli8JNaRxhsqKwwPlReEI/mplzz5IP6gWQ92LogXbdBXtHf9ZpA53BeLmtcNBEY0
Ygd7sPBhlHABS5D5///zltSSX2+L5GCEiC6dpfGsySjqymWF+SZ2PaqfZbkWLmCD
9u4ysueaHf7xbF6txGprNp69efttWxdy+vU5tno7HVxemMZQUalpShFrdAYKKXEo
cV7MtbkQjzubS14gaWGpWCXIl9uNKQeHpLKtre1Qn5Ft/zVpCHmhLQcYDuB1LAj9
7eoev4rIiOE2sfdkvKDlmFxvzq3myYH4o27WwAg9OZ5SBusn2zesKkRCBBEZ55rl
uVknOGHXAgMBAAECggEAZE0U2OxsNxkfXS6+lXswQ5PW7pF90towcsdSPgrniGIu
pKRnHbfKKbuaewOl+zZcpTIRL/rbgUKPtzrHSiJlC36aQyrvvJ/ZWV5ZJvC+vd19
nY/qob65NyrrkHwxRSjmiwGiR9/IaUXI+vUsMUqx5Ph1hawqhZ3sZlEAKR4LeDO8
M+OguG77jLaqj5/SNfi+GwyUDe85de4VfEG4S9HrMQk2Cp66rx0BqDnCLacyFQaI
R0VczMXTU52q0uETmgUr8G9A1SaRc5ZWKAfZwxJTvqdIImWC9E+CY7wm+mZD4FE6
iVzVC0ngcdEd596kTDdU2BPVMluWzLkfqIrTt/5CeQKBgQDzgRzCPNxFtai6RAIi
ekBSHqrDnrbeTaw32GVq5ACk1Zfk2I0svctz1iQ9qJ2SRINpygQhcyJKQ4r/LXi1
7Av9H/d6QV4T2AZzS4WcqBkxxRXFUfARtnKChzuCzNt9tNz4EZiv75RyQmztGZjV
i94+ZvCyqup5be4Svf4MBxin9QKBgQDA9P4nHzFWZakTMei78LGb/4Auc+r0rZp7
8xg8Z92tvrDeJjMdesdhiFrPP1qiSYHnQ81MSWpn6BycBsHZqitejQmYnYput/s4
qG+m7SrkN8WL6rijYsbB+U14VDjMlBlOgcEgjlSNU2oeS+68u+uVI/fgyXcXn4Jq
33TSWSgfGwKBgA2tRdE/G9wqfOShZ0FKfoxePpcoNfs8f5zPYbrkPYkEmjh3VU6b
Bm9mKrjv3JHXmU3608qRLe7f5lG42xvUu0OnZP4P59nTe2FEb6fB5VBfUn63wHUu
OzZLpDMPkJB59SNV0a6oFT1pr7aNhoEQDxaQL5rJcMwLOaEB3OAOEft1AoGASz7+
4Zi7b7rDPVYIMUpCqNfxT6wqovIUPWPmPqAuhXPIm0kAQ+2+VN2MtCc7m+/Ydawu
IiK7GPweNAY6kDxZH00WweolstmSYVzl9Y2lXUwWgGKvUB/T7I7g1Bzb7YOPftsA
ykZW2Kn/xwLLfdQ2oXleT82g4Jh2jmDHuMPF7qMCgYEA6QF45PvOgnrJessgmwO/
dEmkLl07PQYJPGZLaZteuWrvfMrn+AiW5aAdHzhzNaOtNy5B3T7zGUHtgxXegqgd
/QdCVCJgnZUO/zdAxkr22dDn+WEXkL4wgBVStQvvnQp9C2NJcoOExvex5PLzKWQg
WEKt5v3QsUEgVrzkM4K9UbI=
-----END PRIVATE KEY-----
      EOF
    end

    def custom_public_key
      <<-EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt4neYGem4JSbYcpYvCTW
kcYbKisMD5UXhCP5qZc8+SD+oFkPdi6IF23QV7R3/WaQOdwXi5rXDQRGNGIHe7Dw
YZRwAUuQ+f//85bUkl9vi+RghIgunaXxrMko6splhfkmdj2qn2W5Fi5gg/buMrLn
mh3+8WxercRqazaevXn7bVsXcvr1ObZ6Ox1cXpjGUFGpaUoRa3QGCilxKHFezLW5
EI87m0teIGlhqVglyJfbjSkHh6Syra3tUJ+Rbf81aQh5oS0HGA7gdSwI/e3qHr+K
yIjhNrH3ZLyg5Zhcb86t5smB+KNu1sAIPTmeUgbrJ9s3rCpEQgQRGeea5blZJzhh
1wIDAQAB
-----END PUBLIC KEY-----
      EOF
    end

    def default_private_key
      <<-EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxbz0rp+Z7MklMtSkfiRfceOeTOhOgkGqonCL1B0MRzSjA3yf
onvEobQNYv7uyQ+ZMGT9RL7AlUSUxeWF00A/O6kuwfs4JlPS/FMPy/B2V0UmoteT
p40LmclZHpKZs9yKmgkfa5j8Jjvd/VvV1r/DbkHjZetIe07pSnP3EOAG7sjyV7yr
HPvkgG5h/Vn2U19vTsvYIENcj5OCLF7eUSJZ/6m4qem+wZ4/9cau5E2t57oS8bTd
5k00Jn0E+qRVionLVLtHXKnr0nWlGPinL+UhKBMhLA6Olm5Y8W77sYcUSvlJMy4G
mpIvnWFKQE5vim4zKt3dBF256QPmRCWPTQ+sxwIDAQABAoIBAQCG+vrILVjEo3ZK
IY/8L9Ybh3arJzVYg3z4j/1TmVSlUtAodC0AnJ5Yh/FPb5kPFR/MQlQFVnVeL8ei
45Ab6dKAZnftoRDuUPBIoGa7H3WZEzJRnPlFOen+W80DKq3TcqwGhE23hGIzs1BR
QBxUEOlWXZHeI+OBkRd9ZHX2RgdVfhGK1eCRGkxVUx6lygK7RcLSDJgPGvTUL+Gz
xF4D03pDo2r6oghNk3Fbw4GMXMBLfrKfiee/QyBLEkq+nykVioxXO16ShJfxOzM4
Pt6/7XJW7uMBGSblS89svrsn7i+29wcgkX4rGWyswV6xicpLNBEmkYx119QKLGBk
a1QebsYxAoGBAOJL/KEGyO8z9l+b2xzWlAURCNJEqPgeAk6ck7woA+nnj2KH+/51
1vvbQlvdwN1eP753g3eACvro7XQmVpJzqwBqAGyxtgPoI4F+HR++3lIOA+zfZs3p
1R1/4AEN0E16sV54gVmvkoSm9UCUDM4RXDdC/YgjpVyXla7HFp2KSrTvAoGBAN+x
VzK/7hCFod5KZXq/Nfy4/Wg/1GTwzg8eQCUbRJ3jqk0UWvNnhwWTEHfa8ywDSJFi
bNMlTKtdlGKPHB9dGMt9izGoyeybz0RJz8aCLODN9PBr1GSAhWfqFNYgksScEOy9
c7eEn25Q91tanmni38Y0KZU9iOYAcKJR5Xulw3WpAoGAO/3lBVNlJXTjFcmdtvFz
4Dv52LR3Dv/1oJ2F1NXO482Nh5OBTJ401iP0XaJWJNl9kKLiaWW6g3YIrUgUn1Km
vL9dSXN7S2HZN9UVJ3tUOPCaPcuj12bsJpvl6KGe3UtvhhnwQLR45U3Vqr8U/fRA
PC44REUe64MMHX+OEUm+MGUCgYB/4UgyURruAxdIl0twYsOgWLk10dfAZRHH/sk4
7V/Ky45eRlbAc9zyyOJPQrJl5PKlepkwFFDCXtsnhRzUqUo1eu4KU64sP9678V6A
44Z4dgWjNGHVmsupXl7PEwwUrgvW62+t6HmkfVELvsB1VCgNjWCAWw9aPcImaZ9B
ksAtEQKBgQCs2ZwTMQOX0IyBMRxVDD8JLCYMNZPBisGTjtYQv6F1ITZOzAPwJjI8
3FzbcqCWtmbCe6rCd9p9NDU42cuizlSZfO+2emM5CnKdvb0IeHqODfBZm2vYYJ6p
Euy/YLiXxrwHUo1KecuH04+/s6OxEzMnrYxXqvcK9SwcNTwAkDaBUw==
-----END RSA PRIVATE KEY-----
      EOF
    end

    def default_public_key
      <<-EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxbz0rp+Z7MklMtSkfiRf
ceOeTOhOgkGqonCL1B0MRzSjA3yfonvEobQNYv7uyQ+ZMGT9RL7AlUSUxeWF00A/
O6kuwfs4JlPS/FMPy/B2V0UmoteTp40LmclZHpKZs9yKmgkfa5j8Jjvd/VvV1r/D
bkHjZetIe07pSnP3EOAG7sjyV7yrHPvkgG5h/Vn2U19vTsvYIENcj5OCLF7eUSJZ
/6m4qem+wZ4/9cau5E2t57oS8bTd5k00Jn0E+qRVionLVLtHXKnr0nWlGPinL+Uh
KBMhLA6Olm5Y8W77sYcUSvlJMy4GmpIvnWFKQE5vim4zKt3dBF256QPmRCWPTQ+s
xwIDAQAB
-----END PUBLIC KEY-----
      EOF
    end
  end

end
