require 'net/ssh/errors'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex/diffie_hellman_group1_sha1'

module Net::SSH::Transport::Kex
  # A key-exchange service implementing the
  # "diffie-hellman-group-exchange-sha1" key-exchange algorithm.
  class DiffieHellmanGroupExchangeSHA1 < DiffieHellmanGroup1SHA1
    MINIMUM_BITS      = 2048
    MAXIMUM_BITS      = 8192
    CISCO_MAXIMUM_NEED_BITS = 4096

    private

    # Computes the minimum, preferred and maximum group sizes to request,
    # like OpenSSH's kexgex_client.
    def compute_need_bits
      data[:minimum_dh_bits] ||= MINIMUM_BITS
      data[:maximum_dh_bits] = [MAXIMUM_BITS, data[:minimum_dh_bits]].max
      data[:need_bits] = estimate_group_bits(data[:need_bytes] * 8).clamp(data[:minimum_dh_bits], maximum_need_bits)
    end

    # Some Cisco servers fail instead of returning their 4096-bit group when asked for more (OpenSSH bz#2209).
    def maximum_need_bits
      return data[:maximum_dh_bits] unless cisco_server?

      [CISCO_MAXIMUM_NEED_BITS, data[:minimum_dh_bits]].max
    end

    def cisco_server?
      data[:server_version_string].to_s.match?(/\ASSH-[\d.]+-Cisco-1\./)
    end

    # Group size giving at least the given bits of security (NIST SP 800-57),
    # as OpenSSH's dh_estimate.
    def estimate_group_bits(security_bits)
      if security_bits <= 112
        2048
      elsif security_bits <= 128
        3072
      elsif security_bits <= 192
        7680
      else
        8192
      end
    end

    # Returns the DH key parameters for the given session.
    def get_parameters
      compute_need_bits

      # request the DH key parameters for the given number of bits.
      buffer = Net::SSH::Buffer.from(:byte, KEXDH_GEX_REQUEST, :long, data[:minimum_dh_bits],
                                     :long, data[:need_bits], :long, data[:maximum_dh_bits])
      connection.send_message(buffer)

      buffer = connection.next_message
      raise Net::SSH::Exception, "expected KEXDH_GEX_GROUP, got #{buffer.type}" unless buffer.type == KEXDH_GEX_GROUP

      p = buffer.read_bignum
      g = buffer.read_bignum

      validate_group(p, g)

      [p, g]
    end

    def validate_group(prime, generator)
      bits = prime.num_bits
      if bits < data[:minimum_dh_bits]
        raise Net::SSH::Exception,
              "server's DH group is #{bits} bits, below the minimum of #{data[:minimum_dh_bits]}; " \
              "pass minimum_dh_bits: #{bits} to allow it"
      end
      raise Net::SSH::Exception, "server's DH group is #{bits} bits, above the maximum of #{data[:maximum_dh_bits]}" if bits > data[:maximum_dh_bits]
      raise Net::SSH::Exception, "server's DH group generator is invalid" unless generator > 1 && generator < prime - 1
    end

    # Returns the INIT/REPLY constants used by this algorithm.
    def get_message_types
      [KEXDH_GEX_INIT, KEXDH_GEX_REPLY]
    end

    # Build the signature buffer to use when verifying a signature from
    # the server.
    def build_signature_buffer(result)
      response = Net::SSH::Buffer.new
      response.write_string data[:client_version_string],
                            data[:server_version_string],
                            data[:client_algorithm_packet],
                            data[:server_algorithm_packet],
                            result[:key_blob]
      response.write_long data[:minimum_dh_bits],
                          data[:need_bits],
                          data[:maximum_dh_bits]
      response.write_bignum dh.p, dh.g, dh.pub_key,
                            result[:server_dh_pubkey],
                            result[:shared_secret]
      response
    end
  end
end
