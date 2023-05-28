require 'openssl'
require 'delegate'

module Net::SSH::Transport
  # :nodoc:
  # Ruby implementation of AEAD Aes-GCM Mode
  # for Block Ciphers. See RFC5647 for details.
  # The main purpose is the implementation of the GCM iv increment
  module AEADAESGCM
    def self.extended(orig)
      orig.instance_eval do
        @iv = { fixed: nil, invocation_counter: nil }
        orig.padding = 0

        singleton_class.send(:alias_method, :_update, :update)
        singleton_class.send(:private, :_update)
        singleton_class.send(:undef_method, :update)

        def self.block_size
          16
        end

        def iv_len
          12
        end

        def iv=(iv_s)
          if @iv[:fixed].nil?
            @iv[:fixed] = iv_s[0...4]
            @iv[:invocation_counter] = iv_s[4...12]
          end
          super(iv_s)
        end

        def incr_iv
          return if @iv[:fixed].nil?

          @iv[:invocation_counter] = [(@iv[:invocation_counter].unpack1('B*').to_i(2) + 1)].pack('Q>*')
          self.iv = "#{@iv[:fixed]}#{@iv[:invocation_counter]}"
        end

        def padding=(pad)
          # DO NOTHING (always 0)
        end

        def reset
          super
        end

        def final
          super
        end

        def update(data)
          super(data)
        end
      end
    end
  end
end
