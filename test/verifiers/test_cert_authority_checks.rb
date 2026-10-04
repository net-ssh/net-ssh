require "common"
require "net/ssh"
require "net/ssh/verifiers/always"
require "net/ssh/verifiers/accept_new_or_local_tunnel"
require "net/ssh/authentication/certificate"
require "ostruct"

module CertAuthorityCheckFixtures
  CA_KEY = <<~PEM
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAnVJVDoOOYn2Bdk9uyroBJf6HgGK1mFIlqSjBru9xfIJMrVE/
    HcZvuNhwSRv8+P5erSqkdTuZUwxjEb79BDdCHPJourGwChJGGxb3Wo3T8mbAHNi+
    zIKFUWthJLa9HCmFQqpmyPNWKsMcqtzDSd1l73UCTRIa4n07aGWdtaQ35BKP4PGl
    kS/76gkPIB60QkArNh+9p6l1gBmqrP9LXEaM2XUMP7kjW03fsPzo9kqYpJmP+V2I
    HXxBJasbDk6q0yDPp31j3vW6NMjSgSgTs5RAZkPc3/2hGyQ/E6lt6yrKJ7MZGfDS
    s1AAlm916TDELR/PGncDNMbfp4zKXkl4FfqaKwIDAQABAoIBAAZVIBNbfEm+n41x
    mRYT8qPi4PVsA79D3zw15cXy4XCPliKL2KyMJkccfziSJdan9oul4cTOR1eucfZu
    56RZzRF5OHn7WQiuv5+rhv1gJB3nwOfoWZXF0zP5zIk7ydTuXuzWCxkfomJKREck
    Z7/7Z3UCErujdO2U+OU04epD1/QYMwWZC+S1HT45zGbQtTA0M0EnZ+3kNuWP3DKk
    GdZ4kGQU3n8gvD6ygyYgP33tMlVFZrkSPFgZn/s0Tq5f/7dsiBg/wuDkDU63JXm0
    YXsltGAJ059ptOtEQkWPorCJQ/SRDdIo99VCVmwvkJh5BX4kpTcgSBqR8fSosCkb
    bt2QBdECgYEAzMauVPgByL8zkoWnrv8BVoICVDyO/YjcMJeA/DzyOc6KdAzJ37a9
    17aUOoA+hOAI74RusOnnjoHhNwTa8n4Fxo8oLhGxcQhimwIcQ9GA2bB3LyU2te91
    m6dGl2UIZPDbaPLRE4KDzAKSHsJdU+bZE035ZhvHpuc4+g+RfvDwfD8CgYEAxKzK
    pHezJ2RgZEhz6jI5pKIAMZbz9ogmNbeGzWrKPsuFnQ0pjRADVVtRCj8/fCQUzNtR
    TJdYIowVA2mnJOH8/7QBD7KWK8q60egPlCZ5Jhq0c2IlBLIR3ICUf/HbT+GKZ3Ja
    XJKZxhd02JqJ4hcZkt5lO8cWdgYi0wto+5I5VxUCgYEAtmw8e6dgd4SVne8BPa0g
    dP9mscItJAGbHpKpLovgwcyUnOOTp381Sgj1rdP3XgnzC+Tvcx080kAz8P6bSjEo
    VgXMJpZOe8KbjTlpEqV9YvCIjHBbd+J15A81nMM9oibLX4gI55d6b/DOWSaPW6Io
    OcFZ7zPKPY54vJPH6s0bf6MCgYAf5DD72FkZoyIqQMFjEX/dXVOQtvyaVltzzG20
    c4OWCSSCYfcB473WoncSpUzjEWq6CTo2pDfrajGiGwi6Z1bCE+s0I25MbZQ7o1ib
    Wl28uwnVx+1exI025zatRIeefWEXAyj559+9imItGWoQWlSQRzW9KrxOqRIOjMQa
    PwzDPQKBgBT0PXS9xtWOJrSjM14OfgUwv6N0jRLknknKLHma7tyXbFKw1py107Dy
    XptT2M+GhtBGbjCw4sz6GLkgLQLBmKmm0Ktr0BulAIl33j/gYL7UWLeU3703e2Xx
    CAHisz08DFRX3OkU2bsRDhyhJVjydWHhQSlokF9WPR69Lho6Y1HU
    -----END RSA PRIVATE KEY-----
  PEM
  KEY = <<~PEM
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAs1K8+OqjMJCHhfZtgPt/liXAaIUkBQVKm0XZ3oHAycLADyfR
    VFLLYs3Qb6AVUYvyNnTJITiF0gwnxhR1HWWQcXlYbAcGp9C4IOGzSVDetb4ZDpct
    Tf1KVIHijj7NGJxKehy1fUxzT/Osqg2r+dSDjVGC50aknxyaxcNZhGuGG2bXhOML
    DWxHFXlhsD3fEY0PdFovcLu3Z/XrRjj1BX192/qjNGR35YC8IT0OlhgIRhAHe/+d
    MsqqbnWCgrotRowSuwQrbmjpTq8MZRYAUZwcy5QCjFH7LEhblvFaNApZXUDgCHOb
    aA6qfhA1mVyMp3EaPamdumJ49WBbineACOB2eQIDAQABAoIBAGM9XcFvsQJWafn0
    R+PCy3gfylzNmgKBTCmkPY+LRVMjSUDZ61n8O/yhJEIyWLn5dgE3HnwZGM4G1hgk
    CDBNneN+oTWfqcpDkzL3VU40yBvSaXGOro7jpzgfbW8FSGHfVMRBkRsXrRVJKHwv
    9sXbGzahLo2ppb88iFb75lWHX/9XO2Hm9ozY+wPwPrOxqLumcVefBTUbc8nUIC2j
    Qx81wUhPf4xXAnxdtYURhsJOjnznzINBfA0X5p7Ecamy6i1o4n2AgMWdXaPrJiIB
    xNBuFRDdKcDjP4qKbcwXFkARtsy45WPK3gz+Mm61sdUE3XZIGa+oRLSkzMDM81Oh
    e4pmaVECgYEA7ixbkPW67oXX1+DzoTBrKs77s0vM/RaBmDOQrVHqmJN19A5bFEuj
    bqc5z+6cwQmHQz/J8x2WyicrCzROeTDSvQf+AjL4noEjMdeX/YU14Gaz74ntWJ5T
    tvOtFl5iF1ffpoHDFckXTJ1fveF7YudiQ8E7rkw53D7TWXCJbRbQp/UCgYEAwL7A
    zUM9OP1SwyxsMk7+ovtEUh4qfBUiWTq9HGxbEUjhPAjnIQRL1mdLJko3k2oHzNT3
    hTSwu82cd5Zws5+vuNMG2dFQqW62J3d2uIzPrWm8pNlZQsuME/rZBIi212a5UcYZ
    oRYIO7OkVJrbj/m99pimLH4tdV2RazXeTB6CNfUCgYEAgjhOeBticTdMpAOiMOdA
    MM+qXoV7NoUvpf/LgnffRDybqSyQL7CLUtyrhzx3CDQleGdQC1SKNUzlA+M9ZJWF
    I0VTY/Bqbn88tuuhdkN3CZIdn0JSOrmWG9lvMWO5TfoFlgwslaS00Hba+f5mb9UC
    rPjhoJKcsAbJl4UoHjTzMGECgYACQvq+LdjND2PmOGI4oOaqAOrHT+VNuW3CwEax
    y6+x3zoNW0ljAMrnBCVEmMBYMXlP9PvGi1y7h2kbmh9ObERCle9RpPweUNdAVU2G
    Utio/0GgaZB7kSneniXnwLbshh8Mj5eDZV/JW41FFOAYq2SIPThN81kTNHrdWC94
    ky8R9QKBgQDXzGNrXay1Qn4TewdlevK7PNiB9xzkdRGf7pYCh5PWMFWDDJUwo17S
    gTn5Kf77XhIZskNDA12mVZgR+EnDmybHqWybRG3pKc4hmKogKmDTHjnG4M/cVbNE
    zlh8zP2fVxwrdNFkJxn9a+9/qIhkh/if9JhCecajaE9mD3xvOJ1/iA==
    -----END RSA PRIVATE KEY-----
  PEM
  # Generated via `ssh-keygen -s ca -I foobar -V +52w -n root -O no-agent-forwarding -O force-command=/bin/false -z 99 key`.
  SIGNED_CERT = "\x00\x00\x00\x1Cssh-rsa-cert-v01@openssh.com\x00\x00\x00 Ir\xB9\xC9\x94l\x0ER\xA1h\xF5\xFDx\xB2J\xC6g\eHS\xDD\x162\x86\xF1\x90%\\$rf\xAF\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x01\x00\xB3R\xBC\xF8\xEA\xA30\x90\x87\x85\xF6m\x80\xFB\x7F\x96%\xC0h\x85$\x05\x05J\x9BE\xD9\xDE\x81\xC0\xC9\xC2\xC0\x0F'\xD1TR\xCBb\xCD\xD0o\xA0\x15Q\x8B\xF26t\xC9!8\x85\xD2\f'\xC6\x14u\x1De\x90qyXl\a\x06\xA7\xD0\xB8 \xE1\xB3IP\xDE\xB5\xBE\x19\x0E\x97-M\xFDJT\x81\xE2\x8E>\xCD\x18\x9CJz\x1C\xB5}LsO\xF3\xAC\xAA\r\xAB\xF9\xD4\x83\x8DQ\x82\xE7F\xA4\x9F\x1C\x9A\xC5\xC3Y\x84k\x86\ef\xD7\x84\xE3\v\rlG\x15ya\xB0=\xDF\x11\x8D\x0FtZ/p\xBB\xB7g\xF5\xEBF8\xF5\x05}}\xDB\xFA\xA34dw\xE5\x80\xBC!=\x0E\x96\x18\bF\x10\a{\xFF\x9D2\xCA\xAAnu\x82\x82\xBA-F\x8C\x12\xBB\x04+nh\xE9N\xAF\fe\x16\x00Q\x9C\x1C\xCB\x94\x02\x8CQ\xFB,H[\x96\xF1Z4\nY]@\xE0\bs\x9Bh\x0E\xAA~\x105\x99\\\x8C\xA7q\x1A=\xA9\x9D\xBAbx\xF5`[\x8Aw\x80\b\xE0vy\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00\x01\x00\x00\x00\x06foobar\x00\x00\x00\b\x00\x00\x00\x04root\x00\x00\x00\x00Xk\\\x1C\x00\x00\x00\x00ZK>g\x00\x00\x00#\x00\x00\x00\rforce-command\x00\x00\x00\x0E\x00\x00\x00\n/bin/false\x00\x00\x00c\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x16permit-port-forwarding\x00\x00\x00\x00\x00\x00\x00\npermit-pty\x00\x00\x00\x00\x00\x00\x00\x0Epermit-user-rc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x17\x00\x00\x00\assh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x01\x00\x9DRU\x0E\x83\x8Eb}\x81vOn\xCA\xBA\x01%\xFE\x87\x80b\xB5\x98R%\xA9(\xC1\xAE\xEFq|\x82L\xADQ?\x1D\xC6o\xB8\xD8pI\e\xFC\xF8\xFE^\xAD*\xA4u;\x99S\fc\x11\xBE\xFD\x047B\x1C\xF2h\xBA\xB1\xB0\n\x12F\e\x16\xF7Z\x8D\xD3\xF2f\xC0\x1C\xD8\xBE\xCC\x82\x85Qka$\xB6\xBD\x1C)\x85B\xAAf\xC8\xF3V*\xC3\x1C\xAA\xDC\xC3I\xDDe\xEFu\x02M\x12\x1A\xE2};he\x9D\xB5\xA47\xE4\x12\x8F\xE0\xF1\xA5\x91/\xFB\xEA\t\x0F \x1E\xB4B@+6\x1F\xBD\xA7\xA9u\x80\x19\xAA\xAC\xFFK\\F\x8C\xD9u\f?\xB9#[M\xDF\xB0\xFC\xE8\xF6J\x98\xA4\x99\x8F\xF9]\x88\x1D|A%\xAB\e\x0EN\xAA\xD3 \xCF\xA7}c\xDE\xF5\xBA4\xC8\xD2\x81(\x13\xB3\x94@fC\xDC\xDF\xFD\xA1\e$?\x13\xA9m\xEB*\xCA'\xB3\x19\x19\xF0\xD2\xB3P\x00\x96ou\xE90\xC4-\x1F\xCF\x1Aw\x034\xC6\xDF\xA7\x8C\xCA^Ix\x15\xFA\x9A+\x00\x00\x01\x0F\x00\x00\x00\assh-rsa\x00\x00\x01\x00I\b%\x01\xB2\xCC\x87\xD7\e\xC5\x88\x93|\x9D\xEC}\xA4\x86\xD7\xBB\xB6\xD3\x93\xFD\\\xC73\xC2*\aV\xA2\x81\x05J\x91\x9AEKV\n\xB4\xEB\xF3\xBC\xBAr\x16\xE5\x9A\xB9\xDC(0\xB4\x1C\x9F\"\x9E\xF9\x91\xD0\x1F\x9Cp\r*\xE3\x8A\xD3\xB9W$[OI\xD2\x8F8\x9B\xA4\x9E\xFFuGg\x00\xA5\xCD\r\xDB\x95\xEE)_\xC3\xBCi\xA2\xCC\r\x86\xFD\xE9\xE6\x188\x92\xFD\xCC\n\x98t\x8C\x16\xF4O\xF6\xD5\xD4\xB7\\\xB95\x19\xA3\xBBW\xF3\xF7r<\xE6\x8C\xFC\xE5\x9F\xBF\xE0\xBF\x06\xE7v\xF2\x8Ek\xA4\x02\xB6fMd\xA5e\x87\xE1\x93\xF5\x81\xCF\xDF\x88\xDC\a\xA2\e\xD5\xCA\x14\xB2>\xF4\x8F|\xE5-w\xF5\x85\xD0\xF1F((\xD1\xEEE&\x1D\xA2+\xEC\x93\xE7\xC7\xAE\xE38\xE4\xAE\xF7 \xED\xC6\r\xD6\x1A\xE1#<\xA2)j\xB3TA\\\xFF;\xC5\xA6Tu\xAAap\xDE\xF4\xF7 p\xCA\xD2\xBA\xDC\xCDv\x17\xC2\xBCQ\xDF\xAB7^\xA1G\x18\xB9\xB2F\x81\x9Fq\x92\xD3".b
end

# Regression tests for GHSA-vxj5-fg65-x765: the @cert-authority host-certificate
# verifier accepts any CA-signed certificate without enforcing the constraints
# OpenSSH checks in sshkey_cert_check_authority (valid_principals, validity
# window, cert type, critical options). Each test builds a certificate that is
# correctly signed by the trusted CA but that OpenSSH would reject, and asserts
# net-ssh rejects it too. See also net-ssh/net-ssh#988.
module CertAuthorityChecks
  CA_KEY = CertAuthorityCheckFixtures::CA_KEY
  KEY = CertAuthorityCheckFixtures::KEY
  CERT_TEMPLATE = CertAuthorityCheckFixtures::SIGNED_CERT

  class TestCertAuthorityChecks < NetSSHTest
    TARGET = "prod-db.example.com"

    def ca_key
      @ca_key ||= OpenSSL::PKey::RSA.new(CA_KEY)
    end

    def host_key
      @host_key ||= OpenSSL::PKey::RSA.new(KEY)
    end

    # Build a certificate signed by the trusted CA, overriding the fields the
    # verifier is supposed to check.
    def build_cert(type: :host, principals: [TARGET], valid_after: Time.now - 3600,
                   valid_before: Time.now + 3600, critical_options: {})
      cert = Net::SSH::Buffer.new(CERT_TEMPLATE).read_key
      cert.key = host_key
      cert.type = type
      cert.valid_principals = principals
      cert.valid_after = valid_after
      cert.valid_before = valid_before
      cert.critical_options = critical_options
      cert.sign!(ca_key)
      cert
    end

    # A HostKeys collection with a single @cert-authority entry trusting our CA
    # for +host+ — the same object net-ssh builds from a known_hosts file.
    def host_keys_for(host)
      entry = Net::SSH::HostKeyEntries::CertAuthority.new(ca_key)
      Net::SSH::HostKeys.new([entry], host, Net::SSH::KnownHosts, {})
    end

    def verify(verifier, cert, host: TARGET)
      session = OpenStruct.new(host_keys: host_keys_for(host), port: 22, peer: { ip: "1.2.3.4" })
      verifier.verify(session: session, key: cert, fingerprint: "SHA256:test")
    end

    def always
      Net::SSH::Verifiers::Always.new
    end

    # Positive control: a valid, in-window host cert for the target is accepted.
    def test_valid_host_cert_is_accepted
      assert verify(always, build_cert)
    end

    def test_rejects_cert_whose_principals_do_not_include_host
      assert_raises(Net::SSH::HostKeyError) do
        verify(always, build_cert(principals: ["evil.example"]))
      end
    end

    # Host-certificate principals are shell-glob patterns (OpenSSH match_pattern),
    # so a "*.example.com" principal must match the target and nothing outside it.
    def test_accepts_wildcard_principal_matching_host
      assert verify(always, build_cert(principals: ["*.example.com"]))
    end

    def test_rejects_wildcard_principal_for_other_domain
      assert_raises(Net::SSH::HostKeyError) do
        verify(always, build_cert(principals: ["*.evil.com"]))
      end
    end

    def test_rejects_expired_cert
      assert_raises(Net::SSH::HostKeyError) do
        verify(always, build_cert(valid_after: Time.now - 7200, valid_before: Time.now - 3600))
      end
    end

    def test_rejects_not_yet_valid_cert
      assert_raises(Net::SSH::HostKeyError) do
        verify(always, build_cert(valid_after: Time.now + 3600, valid_before: Time.now + 7200))
      end
    end

    def test_rejects_user_cert_for_host_auth
      assert_raises(Net::SSH::HostKeyError) do
        verify(always, build_cert(type: :user))
      end
    end

    def test_rejects_unknown_critical_option
      assert_raises(Net::SSH::HostKeyError) do
        verify(always, build_cert(critical_options: { "totally-unknown-option" => "x" }))
      end
    end

    # The default verifier must not silently accept (and remember!) a cert that
    # fails the above checks. AcceptNew rescues HostKeyUnknown, so a fix that
    # signals rejection only via HostKeyUnknown is a no-op on this path.
    def test_default_verifier_rejects_wrong_principal
      verifier = Net::SSH::Verifiers::AcceptNewOrLocalTunnel.new
      assert_raises(Net::SSH::HostKeyError) do
        verify(verifier, build_cert(principals: ["evil.example"]))
      end
    end
  end
end
