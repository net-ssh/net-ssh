# frozen_string_literal: true

require 'common'
require 'transport/kex/test_diffie_hellman_group1_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group14_sha1'

module Transport
  module Kex
    class TestDiffieHellmanGroupExchangeSHA1 < TestDiffieHellmanGroup1SHA1
      KEXDH_GEX_GROUP   = 31
      KEXDH_GEX_INIT    = 32
      KEXDH_GEX_REPLY   = 33
      KEXDH_GEX_REQUEST = 34

      def test_request_sizes_follow_openssh_estimate
        { 8 => 2048, 14 => 2048, 16 => 3072, 24 => 7680, 32 => 8192, 64 => 8192 }.each do |need_bytes, need_bits|
          setup
          dh_options need_bytes: need_bytes
          assert_nothing_raised { exchange! }
          assert_equal [2048, need_bits, 8192], @request
        end
      end

      def test_minimum_dh_bits_raises_requested_sizes
        dh_options need_bytes: 8, minimum_dh_bits: 4096
        assert_nothing_raised { exchange! p: modulus(4096) }
        assert_equal [4096, 4096, 8192], @request
      end

      def test_cisco_server_caps_preferred_size
        packet_data[:server_version_string] = "SSH-2.0-Cisco-1.25"
        dh_options need_bytes: 32
        assert_nothing_raised { exchange! p: modulus(4096) }
        assert_equal [2048, 4096, 8192], @request
      end

      def test_non_cisco_server_preferred_size_is_not_capped
        packet_data[:server_version_string] = "SSH-2.0-OpenSSH_9.6 Cisco-1.25"
        dh_options need_bytes: 32
        assert_nothing_raised { exchange! }
        assert_equal [2048, 8192, 8192], @request
      end

      def test_cisco_server_preferred_size_stays_at_minimum_dh_bits
        packet_data[:server_version_string] = "SSH-2.0-Cisco-1.25"
        dh_options need_bytes: 32, minimum_dh_bits: 6144
        assert_nothing_raised { exchange! p: modulus(6144) }
        assert_equal [6144, 6144, 8192], @request
      end

      def test_minimum_dh_bits_below_default_accepts_legacy_group
        dh_options minimum_dh_bits: 1024
        assert_nothing_raised { exchange! p: legacy_p }
        assert_equal [1024, 7680, 8192], @request
        assert_equal legacy_p, dh.dh.p
      end

      def test_group_below_minimum_should_raise_exception_naming_opt_out
        error = assert_raises(Net::SSH::Exception) { exchange! p: legacy_p }
        assert_equal "server's DH group is 1024 bits, below the minimum of 2048; pass minimum_dh_bits: 1024 to allow it",
                     error.message
      end

      def test_group_below_custom_minimum_should_raise_exception
        dh_options minimum_dh_bits: 3072
        error = assert_raises(Net::SSH::Exception) { exchange! }
        assert_match(/2048 bits, below the minimum of 3072/, error.message)
      end

      def test_group_above_maximum_should_raise_exception
        error = assert_raises(Net::SSH::Exception) { exchange! p: modulus(8193) }
        assert_equal "server's DH group is 8193 bits, above the maximum of 8192", error.message
      end

      def test_invalid_generator_should_raise_exception
        [0, 1, default_p - 1, default_p].each do |g|
          setup
          error = assert_raises(Net::SSH::Exception) { exchange! g: g }
          assert_equal "server's DH group generator is invalid", error.message
        end
      end

      def test_that_p_and_g_are_provided_by_the_server
        assert_nothing_raised { exchange! p: default_p + 2, g: 3 }
        assert_equal default_p + 2, dh.dh.p
        assert_equal 3, dh.dh.g
      end

      private

      def group_p
        default_p
      end

      def default_p
        OpenSSL::BN.new(Net::SSH::Transport::Kex::DiffieHellmanGroup14SHA1::P_s, 16)
      end

      # 1024-bit group, as offered by legacy servers
      def legacy_p
        OpenSSL::BN.new("142326151570335518660743995281621698377057354949884468943021767573608899048361360422513557553514790045512299468953431585300812548859419857171094366358158903433167915517332113861059747425408670144201099811846875730766487278261498262568348338476437200556998366087779709990807518291581860338635288400119315130179")
      end

      def modulus(bits)
        OpenSSL::BN.new((1 << (bits - 1)) + 0xFFFF_FFFF)
      end

      def exchange!(options = {})
        connection.expect do |t, buffer|
          assert_equal KEXDH_GEX_REQUEST, buffer.type
          @request = [buffer.read_long, buffer.read_long, buffer.read_long]
          t.return(KEXDH_GEX_GROUP, :bignum, bn(options[:p] || default_p), :bignum, bn(options[:g] || 2))
          t.expect do |t2, buffer2|
            assert_equal KEXDH_GEX_INIT, buffer2.type
            assert_equal dh.dh.pub_key, buffer2.read_bignum
            t2.return(KEXDH_GEX_REPLY, :string, options[:server_key_blob] || b(:key, server_key), :bignum, server_dh_pubkey, :string, b(:string, options[:key_type] || "ssh-rsa", :string, signature))
            t2.expect do |t3, buffer3|
              assert_equal NEWKEYS, buffer3.type
              t3.return(NEWKEYS)
            end
          end
        end

        dh.exchange_keys
      end

      def subject
        Net::SSH::Transport::Kex::DiffieHellmanGroupExchangeSHA1
      end

      def digest_type
        OpenSSL::Digest::SHA1
      end

      def session_id
        @session_id ||= begin
          buffer = Net::SSH::Buffer.from(:string, packet_data[:client_version_string],
                                         :string, packet_data[:server_version_string],
                                         :string, packet_data[:client_algorithm_packet],
                                         :string, packet_data[:server_algorithm_packet],
                                         :string, Net::SSH::Buffer.from(:key, server_key),
                                         :long,   @request[0],
                                         :long,   @request[1],
                                         :long,   @request[2],
                                         :bignum, dh.dh.p,
                                         :bignum, dh.dh.g,
                                         :bignum, dh.dh.pub_key,
                                         :bignum, server_dh_pubkey,
                                         :bignum, shared_secret)
          digest_type.digest(buffer.to_s)
        end
      end
    end
  end
end
