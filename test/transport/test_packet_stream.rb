# encoding: ASCII-8BIT

require_relative '../common'
require 'timeout'
require 'zlib'
require 'net/ssh/transport/packet_stream'

module Transport
  class TestPacketStream < NetSSHTest # rubocop:disable Metrics/ClassLength
    include Net::SSH::Transport::Constants

    def test_client_name_when_getnameinfo_works
      stream.expects(:getsockname).returns(:sockaddr)
      Socket.expects(:getnameinfo).with(:sockaddr, Socket::NI_NAMEREQD).returns(["net.ssh.test"])
      assert_equal "net.ssh.test", stream.client_name
    end

    def test_client_name_when_getnameinfo_fails_first_and_then_works
      stream.expects(:getsockname).returns(:sockaddr)
      Socket.expects(:getnameinfo).with(:sockaddr, Socket::NI_NAMEREQD).raises(SocketError)
      Socket.expects(:getnameinfo).with(:sockaddr).returns(["1.2.3.4"])
      assert_equal "1.2.3.4", stream.client_name
    end

    def test_client_name_when_getnameinfo_fails_but_gethostbyname_works
      stream.expects(:getsockname).returns(:sockaddr)
      Socket.expects(:getnameinfo).with(:sockaddr, Socket::NI_NAMEREQD).raises(SocketError)
      Socket.expects(:getnameinfo).with(:sockaddr).raises(SocketError)
      Socket.expects(:gethostname).returns(:hostname)
      Socket.expects(:gethostbyname).with(:hostname).returns(["net.ssh.test"])
      assert_equal "net.ssh.test", stream.client_name
    end

    def test_client_name_when_getnameinfo_and_gethostbyname_all_fail
      stream.expects(:getsockname).returns(:sockaddr)
      Socket.expects(:getnameinfo).with(:sockaddr, Socket::NI_NAMEREQD).raises(SocketError)
      Socket.expects(:getnameinfo).with(:sockaddr).raises(SocketError)
      Socket.expects(:gethostname).returns(:hostname)
      Socket.expects(:gethostbyname).with(:hostname).raises(SocketError)
      assert_equal "unknown", stream.client_name
    end

    def test_peer_ip_should_query_socket_for_info_about_peer
      stream.expects(:getpeername).returns(:sockaddr)
      Socket.expects(:getnameinfo).with(:sockaddr, Socket::NI_NUMERICHOST | Socket::NI_NUMERICSERV).returns(["1.2.3.4"])
      assert_equal "1.2.3.4", stream.peer_ip
    end

    def test_peer_ip_should_return_no_hostip_when_socket_has_no_peername
      assert_equal false, stream.respond_to?(:getpeername)
      assert_equal Net::SSH::Transport::PacketStream::PROXY_COMMAND_HOST_IP, stream.peer_ip
      assert_equal '<no hostip for proxy command>', stream.peer_ip
    end

    def test_available_for_read_should_return_nontrue_when_select_fails
      IO.expects(:select).returns(nil)
      assert !stream.available_for_read?
    end

    def test_available_for_read_should_return_nontrue_when_self_is_not_ready
      IO.expects(:select).with([stream], nil, nil, 0).returns([[], [], []])
      assert !stream.available_for_read?
    end

    def test_available_for_read_should_return_true_when_self_is_ready
      IO.expects(:select).with([stream], nil, nil, 0).returns([[self], [], []])
      assert stream.available_for_read?
    end

    def test_cleanup_should_delegate_cleanup_to_client_and_server_states
      stream.client.expects(:cleanup)
      stream.server.expects(:cleanup)
      stream.expects(:pid)
      stream.cleanup
    end

    def test_if_needs_rekey_should_not_yield_if_neither_client_nor_server_states_need_rekey
      stream.if_needs_rekey? { flunk "shouldn't need rekey" }
      assert(true)
    end

    def test_if_needs_rekey_should_yield_and_cleanup_if_client_needs_rekey
      stream.client.stubs(:needs_rekey?).returns(true)
      stream.client.expects(:reset!)
      stream.server.expects(:reset!).never
      rekeyed = false
      stream.if_needs_rekey? { rekeyed = true }
      assert(rekeyed)
    end

    def test_if_needs_rekey_should_yield_and_cleanup_if_server_needs_rekey
      stream.server.stubs(:needs_rekey?).returns(true)
      stream.server.expects(:reset!)
      stream.client.expects(:reset!).never
      rekeyed = false
      stream.if_needs_rekey? { rekeyed = true }
      assert(rekeyed)
    end

    def test_if_needs_rekey_should_yield_and_cleanup_if_both_need_rekey
      stream.server.stubs(:needs_rekey?).returns(true)
      stream.client.stubs(:needs_rekey?).returns(true)
      stream.server.expects(:reset!)
      stream.client.expects(:reset!)
      rekeyed = false
      stream.if_needs_rekey? { rekeyed = true }
      assert(rekeyed)
    end

    def test_next_packet_should_not_block_by_default
      IO.expects(:select).returns(nil)
      assert_nothing_raised do
        Timeout.timeout(1) { stream.next_packet }
      end
    end

    def test_next_packet_should_return_nil_when_non_blocking_and_not_ready
      IO.expects(:select).returns(nil)
      assert_nil stream.next_packet(:nonblock)
    end

    def test_next_packet_should_return_nil_when_non_blocking_and_partial_read
      IO.expects(:select).returns([[stream]])
      stream.expects(:recv).returns([8].pack("N"))
      assert_nil stream.next_packet(:nonblock)
      assert !stream.read_buffer.empty?
    end

    def test_next_packet_should_return_packet_when_non_blocking_and_full_read
      IO.expects(:select).returns([[stream]])
      stream.expects(:recv).returns(packet)
      packet = stream.next_packet(:nonblock)
      assert_not_nil packet
      assert_equal DEBUG, packet.type
    end

    def test_next_packet_should_eventually_return_packet_when_non_blocking_and_partial_read
      IO.stubs(:select).returns([[stream]])
      stream.stubs(:recv).returns(packet[0, 10], packet[10..-1])
      assert_nil stream.next_packet(:nonblock)
      packet = stream.next_packet(:nonblock)
      assert_not_nil packet
      assert_equal DEBUG, packet.type
    end

    def test_nonblocking_next_packet_should_raise
      IO.stubs(:select).returns([[stream]])
      stream.stubs(:recv).returns("")
      assert_raises(Net::SSH::Disconnect) { stream.next_packet(:nonblock) }
    end

    def test_nonblocking_next_packet_should_return_packet_before_raise
      IO.stubs(:select).returns([[stream]])
      stream.send(:input).append(packet)
      stream.stubs(:recv).returns("")
      packet = stream.next_packet(:nonblock)
      assert_not_nil packet
      assert_equal DEBUG, packet.type
      assert_raises(Net::SSH::Disconnect) { stream.next_packet(:nonblock) }
    end

    def test_next_packet_should_block_when_requested_until_entire_packet_is_available
      IO.stubs(:select).returns([[stream]])
      stream.stubs(:recv).returns(packet[0, 10], packet[10, 20], packet[20..-1])
      packet = stream.next_packet(:block)
      assert_not_nil packet
      assert_equal DEBUG, packet.type
    end

    def test_next_packet_when_blocking_should_fail_when_fill_could_not_read_any_data
      IO.stubs(:select).returns([[stream]])
      stream.stubs(:recv).returns("")
      assert_raises(Net::SSH::Disconnect) { stream.next_packet(:block) }
    end

    def test_next_packet_when_blocking_times_out
      IO.expects(:select).with([stream], nil, nil, 7).returns(nil)
      assert_raises(Net::SSH::ConnectionTimeout) { stream.next_packet(:block, 7) }
    end

    def test_next_packet_fails_with_invalid_argument
      assert_raises(ArgumentError) { stream.next_packet("invalid") }
    end

    def test_send_packet_should_enqueue_and_send_data_immediately
      stream.expects(:send).times(3).with { |a, b| a == stream.write_buffer && b == 0 }.returns(15)
      IO.expects(:select).times(2).returns([[], [stream]])
      stream.send_packet(ssh_packet)
      assert !stream.pending_write?
    end

    def test_enqueue_short_packet_should_ensure_packet_is_at_least_16_bytes_long
      packet = Net::SSH::Buffer.from(:byte, 0)
      stream.enqueue_packet(packet)
      # 12 originally, plus the block-size (8), plus the 4-byte length field
      assert_equal 24, stream.write_buffer.length
    end

    def test_enqueue_utf_8_packet_should_ensure_packet_length_is_in_bytes_and_multiple_of_block_length
      packet = Net::SSH::Buffer.from(:string, "\u2603") # Snowman is 3 bytes
      stream.enqueue_packet(packet)
      # When bytesize is measured wrong using length, the result is off by 2.
      # With length instead of bytesize, you get 26 length buffer.
      assert_equal 0, stream.write_buffer.length % 8
    end

    PACKETS = {
      'chacha20-poly1305@openssh.com' => {
        'implicit' => {
          false => ["5aa01d1e3eff7c277d19f111a384b229fec8652db616d9350d6ef9f51f2011637b60d406673fffad5a647eba"].pack('H*'),
          :standard => ["5aa01d263f83e1451c7d981526aa8e03b3ec44857a5dde471d76ba92fd92c9a77911c43ca96a13e37a5b1a346508016793f4a57a"].pack('H*')
        }
      },
      'aes128-gcm@openssh.com' => {
        'implicit' => {
          false => ["00000020462f5dc27e3ba9da491bbfa70deb5183ffc808c9178e505374ed437b46eb2474c470d68dc015cc677c91794a0d5603a8"].pack('H*'),
          :standard => ["000000204f53c0a01f5fc0decc35838d40cf702b33830fbb07961334235d0cf9001c211636ef2046feff51f3e1d5e7375308896d"].pack('H*')
        }
      },
      'aes256-gcm@openssh.com' => {
        'implicit' => {
          false => ["00000020dfd5571fd6a781e395dcf18552a2b93628bf6a2f3ce456bd08dd3a457094b967d47977a309126e7d02dfc8d5f91a5588"].pack('H*'),
          :standard => ["00000020d6a9ca7db7c3e8e710f2cdaf1f86989ee4f46d5d2cfc15da5f6d75c73663bc056b6644958591f155d06816aa87adbaff"].pack('H*')
        }
      },
      "3des-cbc" => {
        "hmac-md5" => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, \000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200\354=g\361\271[E\265\217\316\314\b\202\235\226\334"
        },
        "hmac-md5-96" => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, \000\032w\312\t\306\374\271\345p\215\224",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200\354=g\361\271[E\265\217\316\314\b"
        },
        "hmac-sha1" => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, \004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200\2117U\266\3444(\235\034\023\377\376\335\301\253rI\215W\311"
        },
        "hmac-sha1-96" => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, \004\a\200\n\004\202z\270\236\261\330m",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200\2117U\266\3444(\235\034\023\377\376"
        },
        "hmac-ripemd160" => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "none" => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, ",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200"
        }
      },
      "aes128-cbc" => {
        "hmac-md5" => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251-\345\b\025\242#\336P8\343\361\263\\\241\326\311"
        },
        "hmac-md5-96" => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251-\345\b\025\242#\336P8\343\361\263"
        },
        "hmac-sha1" => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251yC\272\314@\301\n\346$\223\367\r\026\366\375(i'\212\351"
        },
        "hmac-sha1-96" => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251yC\272\314@\301\n\346$\223\367\r"
        },
        "hmac-ripemd160" => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NYF\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NYF\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "none" => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251"
        }
      },
      "aes192-cbc" => {
        "hmac-md5" => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320D-\345\b\025\242#\336P8\343\361\263\\\241\326\311"
        },
        "hmac-md5-96" => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320D-\345\b\025\242#\336P8\343\361\263"
        },
        "hmac-sha1" => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320DyC\272\314@\301\n\346$\223\367\r\026\366\375(i'\212\351"
        },
        "hmac-sha1-96" => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320DyC\272\314@\301\n\346$\223\367\r"
        },
        "hmac-ripemd160" => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320D\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320D\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "none" => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320D"
        }
      },
      "aes256-cbc" => {
        "hmac-md5" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365-\345\b\025\242#\336P8\343\361\263\\\241\326\311"
        },
        "hmac-md5-96" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365-\345\b\025\242#\336P8\343\361\263"
        },
        "hmac-sha1" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365yC\272\314@\301\n\346$\223\367\r\026\366\375(i'\212\351"
        },
        "hmac-sha1-96" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365yC\272\314@\301\n\346$\223\367\r"
        },
        "hmac-ripemd160" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "none" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365"
        }
      },
      "blowfish-cbc" => {
        "hmac-md5" => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006\354=g\361\271[E\265\217\316\314\b\202\235\226\334"
        },
        "hmac-md5-96" => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006\354=g\361\271[E\265\217\316\314\b"
        },
        "hmac-sha1" => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006\2117U\266\3444(\235\034\023\377\376\335\301\253rI\215W\311"
        },
        "hmac-sha1-96" => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006\2117U\266\3444(\235\034\023\377\376"
        },
        "hmac-ripemd160" => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "none" => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006"
        }
      },
      "cast128-cbc" => {
        "hmac-md5" => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325\354=g\361\271[E\265\217\316\314\b\202\235\226\334"
        },
        "hmac-md5-96" => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325\354=g\361\271[E\265\217\316\314\b"
        },
        "hmac-sha1" => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325\2117U\266\3444(\235\034\023\377\376\335\301\253rI\215W\311"
        },
        "hmac-sha1-96" => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325\2117U\266\3444(\235\034\023\377\376"
        },
        "hmac-ripemd160" => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "none" => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325"
        }
      },
      "idea-cbc" => {
        "hmac-md5" => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317\354=g\361\271[E\265\217\316\314\b\202\235\226\334"
        },
        "hmac-md5-96" => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317\354=g\361\271[E\265\217\316\314\b"
        },
        "hmac-sha1" => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317\2117U\266\3444(\235\034\023\377\376\335\301\253rI\215W\311"
        },
        "hmac-sha1-96" => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317\2117U\266\3444(\235\034\023\377\376"
        },
        "hmac-ripemd160" => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 HF\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 HF\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "none" => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317"
        }
      },
      "3des-ctr" => {
        "hmac-md5" => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94\xFB\xF3\v\xB1",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B\xEC=g\xF1\xB9[E\xB5\x8F\xCE\xCC\b\x82\x9D\x96\xDC"
        },
        "hmac-md5-96" => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B\xEC=g\xF1\xB9[E\xB5\x8F\xCE\xCC\b"
        },
        "hmac-sha1" => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m\xBD\x05\f\x82g\xB0g\xFE",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B\x897U\xB6\xE44(\x9D\x1C\x13\xFF\xFE\xDD\xC1\xABrI\x8DW\xC9"
        },
        "hmac-sha1-96" => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B\x897U\xB6\xE44(\x9D\x1C\x13\xFF\xFE"
        },
        "hmac-ripemd160" => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B)U\xBD\x03U\xDB\x95\x91Y)\xCF\xAE\xA0\xA6\x000\xE9\x1A\xF3Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B)U\xBD\x03U\xDB\x95\x91Y)\xCF\xAE\xA0\xA6\x000\xE9\x1A\xF3Y"
        },
        "none" => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B"
        }
      },
      "blowfish-ctr" => {
        "hmac-md5" => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94\xFB\xF3\v\xB1",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9\xEC=g\xF1\xB9[E\xB5\x8F\xCE\xCC\b\x82\x9D\x96\xDC"
        },
        "hmac-md5-96" => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9\xEC=g\xF1\xB9[E\xB5\x8F\xCE\xCC\b"
        },
        "hmac-sha1" => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m\xBD\x05\f\x82g\xB0g\xFE",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9\x897U\xB6\xE44(\x9D\x1C\x13\xFF\xFE\xDD\xC1\xABrI\x8DW\xC9"
        },
        "hmac-sha1-96" => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9\x897U\xB6\xE44(\x9D\x1C\x13\xFF\xFE"
        },
        "hmac-ripemd160" => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9)U\xBD\x03U\xDB\x95\x91Y)\xCF\xAE\xA0\xA6\x000\xE9\x1A\xF3Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9)U\xBD\x03U\xDB\x95\x91Y)\xCF\xAE\xA0\xA6\x000\xE9\x1A\xF3Y"
        },
        "none" => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9"
        }
      },
      "aes128-ctr" => {
        "hmac-md5" => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94\xFB\xF3\v\xB1",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15-\xE5\b\x15\xA2#\xDEP8\xE3\xF1\xB3\\\xA1\xD6\xC9"
        },
        "hmac-md5-96" => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15-\xE5\b\x15\xA2#\xDEP8\xE3\xF1\xB3"
        },
        "hmac-sha1" => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m\xBD\x05\f\x82g\xB0g\xFE",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15yC\xBA\xCC@\xC1\n\xE6$\x93\xF7\r\x16\xF6\xFD(i'\x8A\xE9"
        },
        "hmac-sha1-96" => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15yC\xBA\xCC@\xC1\n\xE6$\x93\xF7\r"
        },
        "hmac-ripemd160" => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFDF\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15\xC44\x14\xE3q\xEE\x13\x1A\xB2\x81\e9\x8Bd\xB5>^{\xC0\xD0"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFDF\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15\xC44\x14\xE3q\xEE\x13\x1A\xB2\x81\e9\x8Bd\xB5>^{\xC0\xD0"
        },
        "none" => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15"
        }
      },
      "aes192-ctr" => {
        "hmac-md5" => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94\xFB\xF3\v\xB1",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1-\xE5\b\x15\xA2#\xDEP8\xE3\xF1\xB3\\\xA1\xD6\xC9"
        },
        "hmac-md5-96" => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1-\xE5\b\x15\xA2#\xDEP8\xE3\xF1\xB3"
        },
        "hmac-sha1" => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m\xBD\x05\f\x82g\xB0g\xFE",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1yC\xBA\xCC@\xC1\n\xE6$\x93\xF7\r\x16\xF6\xFD(i'\x8A\xE9"
        },
        "hmac-sha1-96" => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1yC\xBA\xCC@\xC1\n\xE6$\x93\xF7\r"
        },
        "hmac-ripemd160" => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1\xC44\x14\xE3q\xEE\x13\x1A\xB2\x81\e9\x8Bd\xB5>^{\xC0\xD0"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1\xC44\x14\xE3q\xEE\x13\x1A\xB2\x81\e9\x8Bd\xB5>^{\xC0\xD0"
        },
        "none" => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1"
        }
      },
      "aes256-ctr" => {
        "hmac-md5" => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94\xFB\xF3\v\xB1",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\n-\xE5\b\x15\xA2#\xDEP8\xE3\xF1\xB3\\\xA1\xD6\xC9"
        },
        "hmac-md5-96" => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\n-\xE5\b\x15\xA2#\xDEP8\xE3\xF1\xB3"
        },
        "hmac-sha1" => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m\xBD\x05\f\x82g\xB0g\xFE",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\nyC\xBA\xCC@\xC1\n\xE6$\x93\xF7\r\x16\xF6\xFD(i'\x8A\xE9"
        },
        "hmac-sha1-96" => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\nyC\xBA\xCC@\xC1\n\xE6$\x93\xF7\r"
        },
        "hmac-ripemd160" => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\rF\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\n\xC44\x14\xE3q\xEE\x13\x1A\xB2\x81\e9\x8Bd\xB5>^{\xC0\xD0"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\rF\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\n\xC44\x14\xE3q\xEE\x13\x1A\xB2\x81\e9\x8Bd\xB5>^{\xC0\xD0"
        },
        "none" => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\n"
        }
      },
      "cast128-ctr" => {
        "hmac-md5" => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94\xFB\xF3\v\xB1",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA\xEC=g\xF1\xB9[E\xB5\x8F\xCE\xCC\b\x82\x9D\x96\xDC"
        },
        "hmac-md5-96" => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7\x00\x1Aw\xCA\t\xC6\xFC\xB9\xE5p\x8D\x94",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA\xEC=g\xF1\xB9[E\xB5\x8F\xCE\xCC\b"
        },
        "hmac-sha1" => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m\xBD\x05\f\x82g\xB0g\xFE",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA\x897U\xB6\xE44(\x9D\x1C\x13\xFF\xFE\xDD\xC1\xABrI\x8DW\xC9"
        },
        "hmac-sha1-96" => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7\x04\a\x80\n\x04\x82z\xB8\x9E\xB1\xD8m",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA\x897U\xB6\xE44(\x9D\x1C\x13\xFF\xFE"
        },
        "hmac-ripemd160" => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA)U\xBD\x03U\xDB\x95\x91Y)\xCF\xAE\xA0\xA6\x000\xE9\x1A\xF3Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7F\xC3\xC7\x87\xA5\x86\xD5~\xCD(\xF8\xD9\xCB\xC5\vHI\xCAL\x8E",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA)U\xBD\x03U\xDB\x95\x91Y)\xCF\xAE\xA0\xA6\x000\xE9\x1A\xF3Y"
        },
        "none" => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA"
        }
      },
      "none" => {
        "hmac-md5" => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^\354=g\361\271[E\265\217\316\314\b\202\235\226\334"
        },
        "hmac-md5-96" => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^\354=g\361\271[E\265\217\316\314\b"
        },
        "hmac-sha1-96" => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^\2117U\266\3444(\235\034\023\377\376"
        },
        "hmac-sha1" => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^\2117U\266\3444(\235\034\023\377\376\335\301\253rI\215W\311"
        },
        "hmac-ripemd160" => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^)U\275\003U\333\225\221Y)\317\256\240\246\0000\351\032\363Y"
        },
        "none" => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^"
        }
      },
      "rijndael-cbc@lysator.liu.se" => {
        "hmac-md5" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\000\032w\312\t\306\374\271\345p\215\224\373\363\v\261",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365-\345\b\025\242#\336P8\343\361\263\\\241\326\311"
        },
        "hmac-md5-96" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\000\032w\312\t\306\374\271\345p\215\224",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365-\345\b\025\242#\336P8\343\361\263"
        },
        "hmac-sha1" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\004\a\200\n\004\202z\270\236\261\330m\275\005\f\202g\260g\376",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365yC\272\314@\301\n\346$\223\367\r\026\366\375(i'\212\351"
        },
        "hmac-sha1-96" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340\004\a\200\n\004\202z\270\236\261\330m",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365yC\272\314@\301\n\346$\223\367\r"
        },
        "hmac-ripemd160" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "hmac-ripemd160@openssh.com" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340F\303\307\207\245\206\325~\315(\370\331\313\305\vHI\312L\216",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\3044\024\343q\356\023\032\262\201\e9\213d\265>^{\300\320"
        },
        "none" => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365"
        }
      }
    }

    sha2_packets = {
      '3des-cbc' => {
        'hmac-sha2-256' => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, 7{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200\367F\231v\265o\f9$\224\201\e\364+\226H\374\377=\ts\202`\026\e,\347\t\217\206t\307"
        },
        'hmac-sha2-256-96' => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, 7{\320\316\365Wy\"c\036y\260",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200\367F\231v\265o\f9$\224\201\e"
        },
        'hmac-sha2-512' => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, #/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200Q\3112O\223\361\216\235\022\216\0162\256\343\214\320\v\321\366/$\017]2\302\3435\217\324\245\037\301\225p\270\221c\307\302u\213b 4#\202PFI\371\267l\374\311\001\262z(\335|\334\2446\226"
        },
        'hmac-sha2-512-96' => {
          false => "\003\352\031\261k\243\200\204\301\203]!\a\306\217\201\a[^\304\317\322\264\265~\361\017\n\205\272, #/\317\000\340I\274\363_\225U*",
          :standard => "\317\222v\316\234<\310\377\310\034\346\351\020:\025{\372PDS\246\344\312J\364\301\n\262\r<\037\231Mu\031\240\255\026\362\200Q\3112O\223\361\216\235\022\216\0162"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18n\v\xF0\xD3\xCE,\xD5)\xEC\xE4\xA0\xCC\x9DK\x7F\x99\x03\xCE\x9E\x19\xBD\xFA\xED\x93|\xC0Y\x86\xE4\xA7\x91\x9B^\x97\x91\xBD\xEA+\xA2\x1FE\x7FK\xA2\f\xD2\x8A\x14\xD5\xB7\xD1\xF3\xE8\x95\xE7C",
          :standard => "\x00\x00\x00 \xF51]F\xB2\x1E\xF8CM=\x85\xDC\x86w\xE0\x19s\x81\xF8\xBBT\x11\xC4\x81\x9A\xC5-tc\xE7\n\xC8\xA8l\xE5Y\t4\xFB\xD5\xCC\xF1\xF8\e\xE8\xC54\xDC\x84\xFC\e8pl\xD6\xF7\xF5_\xFA\xE9Cp\xC0P"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18n\v\xF0\xD3\xCE,\xD5)\xEC\xE4\xA0\xCC\x9DK\x7F\x99\x03\xCE\x9E\x19\xBD\xFA\xED\x93[\x90|\xD8\e\xE1u\x9D1t\x91\e\xB6K\\WH\x97\xE4\x8F0\xED\xF6y\xA5(\x15a\xCB\xDA\xA0\x05\x8A)V\x8E\x9CLN\xA3\x95g7v($\x86l\xE691\xEB\xA5\xFC\x1EG\x91\xCA*\xD7\x01\xBE\xAA\"",
          :standard => "\x00\x00\x00 \xF51]F\xB2\x1E\xF8CM=\x85\xDC\x86w\xE0\x19s\x81\xF8\xBBT\x11\xC4\x81\x9A\xC5-tc\xE7\n\xC8~;\x97\t\x83N|\xA8h8\xBD\x8F\xA9v<\"\xE1\xC5\xE0\x81)\xEC^\xD1\xC2\n&\xC4r\xA6\xCFPr\xC8VB\r\x01a\x98?\x97\xDB<\xCD{\xC2@\xA8%\xE1\xD9\xEE^{9\xACwL\e\x8D\x96s\xB7"
        }
      },
      'aes128-cbc' => {
        'hmac-sha2-256' => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY7{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251\373\035\334\340M\032B\307\324\232\211m'\347k\253\371\341\326\254\356\263[\2412\302R\320\274\365\255\003"
        },
        'hmac-sha2-256-96' => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY7{\320\316\365Wy\"c\036y\260",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251\373\035\334\340M\032B\307\324\232\211m"
        },
        'hmac-sha2-512' => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251N\005f\275u\230\344xF\354+RSTS\360\235\004\311$cW\357o\"fy\031\321yX\tYK\347\363kd\a\022\307r\177[ \274\0164\222\300 \037\330<\264\001^\246\337\004\365\233\202\310"
        },
        'hmac-sha2-512-96' => {
          false => "\240\016\243k]0\330\253\030\320\334\261(\034E\211\230#\326\374\267\311O\211E(\234\325n\306NY#/\317\000\340I\274\363_\225U*",
          :standard => "\273\367\324\032\3762\334\026\r\246\342\022\016\325\024\270.\273\005\314\036\312\211\261\037A\361\362:W\316\352K\204\216b\2124>A\265g\331\177\233dK\251N\005f\275u\230\344xF\354+R"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00 \xA8\xD1\xBB\xFDLW\xC57k\x8B{\xE0^'\x8B\xB6s\x87\x87\xAE\x9D\xC0\x8B\x18H\xF2qe\xA4\xF06\xBF\xE7A\xEF\x8CJ\x14\xBB\xECC.\xF3\x98Rn\x9A$\xF9W\x16\xBC\xEE\xDDY{>\x1F\xE0$\xFCao<",
          :standard => "\x00\x00\x00 )\x10,\x8C\x85\r\a\x02I\xE3\xAE\xF6\xA7+\xEC\x11\xF9\x8C\xB9\xAE\xAAe6\x9F\x9Cn\xF2\x7F\xA6\xE8\xE6\xDB`\xB3\xCD\xF6\"\x95\xEA\x9A\xAA9\xB8\x91&\xA0\xCCV\x87\x97\xE6cU\x03\xC0(\xEC6\x9F\t\xE9\xAB\x9Az"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00 \xA8\xD1\xBB\xFDLW\xC57k\x8B{\xE0^'\x8B\xB6s\x87\x87\xAE\x9D\xC0\x8B\x18H\xF2qe\xA4\xF06\xBFu\xCBV\xAE\xE41\xD2Z\xC3\x14)\xF3\x9E\x84R\xC5\x11\xB8zr\xF5\xDD\x87h\xD1\xA8>\xA1F*%W#\xAC|~\bQ\xA6\xF1\xAE\xD7\x807\xBE\xFCq\x1D\xA7\xDEw#\xC28w\x8E\xE3Q\x83}\xE5l\x1F\xD1",
          :standard => "\x00\x00\x00 )\x10,\x8C\x85\r\a\x02I\xE3\xAE\xF6\xA7+\xEC\x11\xF9\x8C\xB9\xAE\xAAe6\x9F\x9Cn\xF2\x7F\xA6\xE8\xE6\xDB\xA7\xBB.\x93I5\xDF&\xD0\x98e\x8C\x87\xC7?\xD6|\x9C[\xFB\xE6\xE1T\t:\xC2w7\x16U\xD4V\x93N\xEDE\x03kGZ\xA4\xE9\xE42\xE5\x8E\x96\xDD\x9B*\xE0\x92L\x1A\xCE\x8D\xE9\xF7\xA1\xBC\xF0\xC9\xF2z"
        }
      },
      'aes192-cbc' => {
        'hmac-sha2-256' => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\0037{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320D\373\035\334\340M\032B\307\324\232\211m'\347k\253\371\341\326\254\356\263[\2412\302R\320\274\365\255\003"
        },
        'hmac-sha2-512' => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320DN\005f\275u\230\344xF\354+RSTS\360\235\004\311$cW\357o\"fy\031\321yX\tYK\347\363kd\a\022\307r\177[ \274\0164\222\300 \037\330<\264\001^\246\337\004\365\233\202\310"
        },
        'hmac-sha2-256-96' => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\0037{\320\316\365Wy\"c\036y\260",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320D\373\035\334\340M\032B\307\324\232\211m"
        },
        'hmac-sha2-512-96' => {
          false => "P$\377\302\326\262\276\215\206\343&\257#\315>Mp\232P\345o\215\330\213\t\027\300\360\300\037\267\003#/\317\000\340I\274\363_\225U*",
          :standard => "se\347\230\026\311\212\250yH\241\302n\364:\276\270M=H1\317\222^\362\237D\225N\354:\343\205M\006[\313$U/yZ\330\235\032\307\320DN\005f\275u\230\344xF\354+R"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00 \x9F\xB2\v\xB0\xEDq\xE0V\x04\xBAJ\xE3\f\x19EFRs\xB2r\xB3'>\xF0\x96\xC8\a\np\xDED~\xA1=mQ\xDF\xF4L\x9A\xF1\xF3%S\xB1\xE4\x03\x9D\x04^\x022O'W\x9E\xCFD\xFF\xF5u\xFF\x16\a",
          :standard => "\x00\x00\x00 \xA5\x89\xA2\xF4\x85\xDD\xED\xC3=\x87\xAD\x81\x83~tV|\x90IH-\xA8\xF5$9\xE8Q\x88i\x9FL|u\xA1\x9F>[\xAA^\xF7L\xE9\x84\x94E\xC3\xD3\x9C\xB9\xB7.VsE\xD4\xA9\xB5\x924\xF4\xE4`\x00U"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00 \x9F\xB2\v\xB0\xEDq\xE0V\x04\xBAJ\xE3\f\x19EFRs\xB2r\xB3'>\xF0\x96\xC8\a\np\xDED~pp\b\x84F\x1A\xBE;\xE2\xAB4\vP$\xB6\xB5\xBAHDX\xE8\x81&G\xB5\xA3\xDA\xDC\v\x17\xC3\x99\xC5\xAD\xE6IR\xDC\x023\r\e)\xFDV\xB4\xCCV\xB5\x98\xB0$\xAB\xE0\x148\x8Ea\xF2x\x85\r\xDAv",
          :standard => "\x00\x00\x00 \xA5\x89\xA2\xF4\x85\xDD\xED\xC3=\x87\xAD\x81\x83~tV|\x90IH-\xA8\xF5$9\xE8Q\x88i\x9FL|\xF7\xFE\x8C#HX\xD11\x81\xF8\x1Du\xD7;\xE0\a\xDB?\x002\xA9\xC2\x80\xC7m$[\x90vD\xB6\xCA\xD1\b\x11\xE0\xFE\xC7O\x9F\xCB\xB0\x97$\x92\xF2\x90\x8B$\xF3BM\x06B\xA4\xB1\x10L!\xD6*ud\x10"
        }
      },
      'aes256-cbc' => {
        'hmac-sha2-256' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\3407{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\373\035\334\340M\032B\307\324\232\211m'\347k\253\371\341\326\254\356\263[\2412\302R\320\274\365\255\003"
        },
        'hmac-sha2-256-96' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\3407{\320\316\365Wy\"c\036y\260",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\373\035\334\340M\032B\307\324\232\211m"
        },
        'hmac-sha2-512' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365N\005f\275u\230\344xF\354+RSTS\360\235\004\311$cW\357o\"fy\031\321yX\tYK\347\363kd\a\022\307r\177[ \274\0164\222\300 \037\330<\264\001^\246\337\004\365\233\202\310"
        },
        'hmac-sha2-512-96' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340#/\317\000\340I\274\363_\225U*",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365N\005f\275u\230\344xF\354+R"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00 \xDF'\xE2\xE7\xF6.\x92\x9F\xBA)N\xFE\xA0\xCC\x9A\x9Ai{\xB5\r\f\x18\xFA\xA9\x89\x9B\xD3\xF0zXK^\xFF\xB9\x14\xF1?\x0Ez\xF5\x8A\t~x\xCC\xFFj\x15\xE8\"\xA1dUd\xA4\xA5?\xF0\x1E\xE9\x82\xE2R\a",
          :standard => "\x00\x00\x00 1\xFC\xCAD\x0E\x97\x7F\xC51\xB0\b\xE1\xE7\xAC\x90\x9E\xCD\xB2\x88\x84d*\xD5E\xE1\x15\xC9\xBE\xCB\x8D\x14^\x9A\xC4v\xAA\xA7\x19L\x0E\xCBX;\xEDh\xDC\xCD\xD0\xB4#>\x8B\x7F\xB6\x97U\x84\x9CB\x84\xB1]\x1Co"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00 \xDF'\xE2\xE7\xF6.\x92\x9F\xBA)N\xFE\xA0\xCC\x9A\x9Ai{\xB5\r\f\x18\xFA\xA9\x89\x9B\xD3\xF0zXK^>\xE2\xDE\x95]\xD4\f%gBo3\x95\xD7\xFBF\xD8\xC5\x18R\x10\xB0\xA6i\xB8\ej\xAA}?\xF8\xA7\xB2K\x9E\xE3\b\xA5.D\x94\x04,\xB1\xFA\x92\xAA\xA9`\x95\x19\xC7P\x92r<\xCB\x93\xD9\xD8Nu\x89\b",
          :standard => "\x00\x00\x00 1\xFC\xCAD\x0E\x97\x7F\xC51\xB0\b\xE1\xE7\xAC\x90\x9E\xCD\xB2\x88\x84d*\xD5E\xE1\x15\xC9\xBE\xCB\x8D\x14^\xF8\xD2x\x817\x7F#b\xEC\x96\xB9\xE2pG\x9BI\bQ\xC0\xA8\xB6$\xA8]\x05?e\xE5\x86S\x0Fw\xA4Q\xAFW\xFE>\x9B7:\eF\n\xDF\xB1\x85M\xA5N\xCC^\xC9\xA6\xCDp\xBA\x13>\xB9\xEB~\x87\xEB"
        }
      },
      'blowfish-cbc' => {
        'hmac-sha2-256' => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)7{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006\367F\231v\265o\f9$\224\201\e\364+\226H\374\377=\ts\202`\026\e,\347\t\217\206t\307"
        },
        'hmac-sha2-256-96' => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)7{\320\316\365Wy\"c\036y\260",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006\367F\231v\265o\f9$\224\201\e"
        },
        'hmac-sha2-512' => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006Q\3112O\223\361\216\235\022\216\0162\256\343\214\320\v\321\366/$\017]2\302\3435\217\324\245\037\301\225p\270\221c\307\302u\213b 4#\202PFI\371\267l\374\311\001\262z(\335|\334\2446\226"
        },
        'hmac-sha2-512-96' => {
          false => "vT\353\203\247\206L\255e\371\001 6B/\234g\332\371\224l\227\257\346\373E\237C2\212u)#/\317\000\340I\274\363_\225U*",
          :standard => "U\257\231e\347\274\bh\016X\232h\334\v\005\316e1G$-\367##\256$rW\000\210\335_\360\f\000\205#\370\201\006Q\3112O\223\361\216\235\022\216\0162"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\x86\xB4\xFC\xB0\x1F\x93\xFB\xFF\xF6P\xF9ro\xF7\xB8\x87~l)q\x04dK&I\xFC\xEBQ\xC8\xFCO\"\x8D\x87\x98i\x92\xA7\xD8\xC9L\xE4Q\x91\xC6u\xA8\x06\xBEJK\xAEc&C\xFD",
          :standard => "\x00\x00\x00 \xCA@\xF0\xE1\xADdf|\v\x0E\xEEt\xE7\xCD!\x90c\xA5\xCDE\x81\xD0\xBC\xDC7\xF8Y\xA0\xE7^\x1E\xDA.\x9F=\x8A\xB7\xC5%u\xEF\n\xB6F\xCBw\xA30s>cDl\x1AP\x18I[\xFC<=\xCBm\xAF"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\x86\xB4\xFC\xB0\x1F\x93\xFB\xFF\xF6P\xF9ro\xF7\xB8\x87~l)q\x04dK&\x84\xC75!\xB9\x04gt\xD8\xF7]\x82\xC9\x93EvP4\xF1*\x19C3\xFBD_!\x1F\f\xE3#9\xA2\xA2\xB6P\xE4\x89\xAB\x89|kK$\xCE\x18\\F\x90\xB3\x88\x83\xA9\\\x9C\x86\x87E\xA3\x8BX\xEB%7",
          :standard => "\x00\x00\x00 \xCA@\xF0\xE1\xADdf|\v\x0E\xEEt\xE7\xCD!\x90c\xA5\xCDE\x81\xD0\xBC\xDC7\xF8Y\xA0\xE7^\x1E\xDA$\xE3\xEA|\x7F\"zF\x92\e%\x0EpYI\t\xA8R\xA1\x15\xB9\xA8\xA4\x91\xAA\x9CD>\x8B\xE8\xA2\xC9\x85\x00\x94\xDE\xBD\x9C\x8E+\x98\xEE\x91\x9Eb\xFE\x15\xD0X\xD8\xD0=\xF7j\x9C@\xAC_\x94[\x8D,7\f"
        }
      },
      'cast128-cbc' => {
        'hmac-sha2-256' => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\3767{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325\367F\231v\265o\f9$\224\201\e\364+\226H\374\377=\ts\202`\026\e,\347\t\217\206t\307"
        },
        'hmac-sha2-256-96' => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\3767{\320\316\365Wy\"c\036y\260",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325\367F\231v\265o\f9$\224\201\e"
        },
        'hmac-sha2-512' => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325Q\3112O\223\361\216\235\022\216\0162\256\343\214\320\v\321\366/$\017]2\302\3435\217\324\245\037\301\225p\270\221c\307\302u\213b 4#\202PFI\371\267l\374\311\001\262z(\335|\334\2446\226"
        },
        'hmac-sha2-512-96' => {
          false => "\361\026\313!\31235|w~\n\261\257\277\e\277b\246b\342\333\eE\021N\345\343m\314\272\315\376#/\317\000\340I\274\363_\225U*",
          :standard => "\375i\253\004\311E\2011)\220$\251A\245\f(\371\263\314\242\353\260\272\367\276\"\031\224$\244\311W\307Oe\224\0017\336\325Q\3112O\223\361\216\235\022\216\0162"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xC1`!\xB4q\x13\xBD\x8B\xA7x\xD4\x9A\x85\xE9;#\x7FX\xA2`\x939\xE8\x8B{s\xB7Kwo\x19\"\xB8\xAD\xA1\xB1k\xB6\x00\xFAc\xF9\xC4\x0E\xC0\xAF*m\bOW\xE9=\xD4\xF3\xB4",
          :standard => "\x00\x00\x00 \x98\x80\xFA\xB7'\x90\x9D'\xAE\x95s[\xDA,}\xACdpu[\xB1$\x8C\x8Cu<}k`\x84\xEE\xA6A\xD2qGow\xCE\x1F\x16c\xF1qx\xA4\x97\x03K\x93\xC86\xD6?\"k\xAD\xCD\x8D\xA9\x8E\xBFAZ"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xC1`!\xB4q\x13\xBD\x8B\xA7x\xD4\x9A\x85\xE9;#\x7FX\xA2`\x939\xE8\x8B\xDF\xF7\xF4\xD3\x9E\xC3\"\xAD\xB2\xD6&*\x03.#\x1A\xB1s\x8E\x18I\x0F\x83*\xE8.#\xDE\x19\xFF \xCF\x9C\xFE&\xDDQ\xEA\xFD\x12\x8A\f\xE9\xD6\xF1\xDA}\x16\xE5\xEF\x10\xD4B\f\v@1\x04\xA5&r\xB03\xC0",
          :standard => "\x00\x00\x00 \x98\x80\xFA\xB7'\x90\x9D'\xAE\x95s[\xDA,}\xACdpu[\xB1$\x8C\x8Cu<}k`\x84\xEE\xA6\xF8P`\x00m\x93\x1Dz\xDD\xA3\xAE\xD4>\xC3y\xD6\x86\x00Osv\x02z\xFE\xE6\xD5\x85\x80\x02<\x8F_8B\xD0\x89\xA1[\xFE\xA8qX\xFE)\xDAf\xA7\x8A\xE5\xF7\xECCY$!s\xD9!\xA7\xDB\x84\x8Fq\x8F"
        }
      },
      'idea-cbc' => {
        'hmac-sha2-256' => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H7{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317\367F\231v\265o\f9$\224\201\e\364+\226H\374\377=\ts\202`\026\e,\347\t\217\206t\307"
        },
        'hmac-sha2-512' => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317Q\3112O\223\361\216\235\022\216\0162\256\343\214\320\v\321\366/$\017]2\302\3435\217\324\245\037\301\225p\270\221c\307\302u\213b 4#\202PFI\371\267l\374\311\001\262z(\335|\334\2446\226"
        },
        'hmac-sha2-256-96' => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H7{\320\316\365Wy\"c\036y\260",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317\367F\231v\265o\f9$\224\201\e"
        },
        'hmac-sha2-512-96' => {
          false => "\342\255\202$\273\201\025#\245\2341F\263\005@{\000<\266&s\016\251NH=J\322/\220 H#/\317\000\340I\274\363_\225U*",
          :standard => "F\3048\360\357\265\215I\021)\a\254/\315%\354M\004\330\006\356\vFr\250K\225\223x\277+Q)\022\327\311K\025\322\317Q\3112O\223\361\216\235\022\216\0162"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xD3~\x94JDl\x94\xBBN6\x922^YN{j\x04r\xE6\x96UCzn\xD6\x0E\x80\xA9\xB9\x06\xB8\xCD\x18\x1A\x17\xAA\xB5\xDFV_\x96\x981\xD4 \x97\x043|\xFB6\x84Yz\xC3",
          :standard => "\x00\x00\x00 \xBATT\xEC\xA5k\xF2\xCA\x8Fp\xE3\xF2\xB8Qtm\x82\x86Z\xFB\x95V\x1CWo\x89\x1D\b\xB0\xCA\x8FS\xBE\xFA\\\x01\x7F\x82\xFE\xBC\xD3G\x88J@\f\xF6\xC2\xA0\a\xCA\xACuQ\x8A \x87c\xABMO\xF5\xD0\""
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xD3~\x94JDl\x94\xBBN6\x922^YN{j\x04r\xE6\x96UCz^\xED\x8E\x949=\xD7\xB4\x8C\n]\x1DY\xF9He\x8C\xC4$\xB2\xE2\xBB\x8F\xDA\xC6\x14\\\xCCe\xB9\xA3\x10\xB6n\x9Cl\xC5/e\xEBP#_\bAP\xD3\xA5Y{#\xCC0g\x96J\x87)\x17\xBB\xBC\x8B=\f",
          :standard => "\x00\x00\x00 \xBATT\xEC\xA5k\xF2\xCA\x8Fp\xE3\xF2\xB8Qtm\x82\x86Z\xFB\x95V\x1CWo\x89\x1D\b\xB0\xCA\x8FS\x8Bi\xE5\xDB\x16\x9F[N\f\xEB\x96k\x1C\xA5{\x9F\xFB\xB1$\xEA\xF0\x7F\xA5\xA7\x99(3\xFC+\xD2%\xB7\a\xEEu\x97\xF9\x98x\xB5\xFF\"I\xBEo\t\xCE?\xF5f^\x87\"?\x18\x89$\xF8\xB0j\xEBnO\x15"
        }
      },
      '3des-ctr' => {
        'hmac-sha2-256' => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB17{\xD0\xCE\xF5Wy\"c\x1Ey\xB0-\xBD\xCA~\x8F\x10U\xED\x01\xFF\x95F\xE5\x86\xAD\xC7\x13N\xE8J",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B\xF7F\x99v\xB5o\f9$\x94\x81\e\xF4+\x96H\xFC\xFF=\ts\x82`\x16\e,\xE7\t\x8F\x86t\xC7"
        },
        'hmac-sha2-256-96' => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB17{\xD0\xCE\xF5Wy\"c\x1Ey\xB0",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91B\xF7F\x99v\xB5o\f9$\x94\x81\e"
        },
        'hmac-sha2-512' => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1#/\xCF\x00\xE0I\xBC\xF3_\x95U*\xD7z\x81\xCEc\xC3\xBDA\xF2\xD8^J\xBF\xC05oI\xBA\xF2\xEA\x86\xF8h\x8B\xB2\xC89\xC8v\x1F\x04\x12\x80]&\xF5\xC8\xC0\x90D[\xE8\x1E\x95\x89\xEB\xF1\xF6\x9F\xB7\x84\xD5",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91BQ\xC92O\x93\xF1\x8E\x9D\x12\x8E\x0E2\xAE\xE3\x8C\xD0\v\xD1\xF6/$\x0F]2\xC2\xE35\x8F\xD4\xA5\x1F\xC1\x95p\xB8\x91c\xC7\xC2u\x8Bb 4#\x82PFI\xF9\xB7l\xFC\xC9\x01\xB2z(\xDD|\xDC\xA46\x96"
        },
        'hmac-sha2-512-96' => {
          false => "\xED#\x86\xD5\xE1mP\v\f\xB9\xC1\xE6\xFD\xA0~,\xD3\x13\x12\x8Cp\xD4F\x92\xCB\xB6R>\xFA]\x9B\xB1#/\xCF\x00\xE0I\xBC\xF3_\x95U*",
          :standard => "\xED#\x86\xED\xE0\x11\xCDim\xDD\xA8\xE2x\x8EB\x06\x9E73$\xBC\x9FA\xE0\xDB\xAE\x11Y\xAD\xED\xD43\x86N\x89\xFE\x14V\x91BQ\xC92O\x93\xF1\x8E\x9D\x12\x8E\x0E2"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xE9'\x87\xC9\xE9iXoi\xDB\xBD\xE5\xFF\xABe,\xB4z|\xEBx\xCC\x05\xF5\xF9\xB7t\x87\x9Frz\x81\x91\x91\xB4\x96j\x92NA1\x85\xDATA\xB4\xA0W\xBDI\xE4$\xCDh&\t",
          :standard => "\x00\x00\x00 \xE8[\x1A\xAB\x88\r1k\xEC\xF5\x81\xCF\xB2\x8FD\x84x1{\x99h\xD4F\x92\xC3Q\xEEQ\xB5QLl\xFBU\xEE\xC3s\xBEoG\xBC\xC9\xF4\xA2\x86\xE7G\xAF\x18n5\xB1\xBD.\xC3\x82\xA3QC\xBC99%."
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xE9'\x87\xC9\xE9iXoi\xDB\xBD\xE5\xFF\xABe,\xB4z|\xEBx\xCC\x05\xF5\x80\xA28\x81L\xDE0\xF9\xB6+'\x1D\xAD\xA7i\xE3\xB9\xDD\x04f\x05\xB5~\xBD\xF0\xDD\xF0\xDB2:_-\xB2\xCC\xA8}O\x0Ey\xF7\x93\x00\xBE\xF2\xA0\xA3^`\xE4\xEAd\xF9;\x99\aq\xBD\xBB\xA5\xA4'\xF4\x8E\x1A",
          :standard => "\x00\x00\x00 \xE8[\x1A\xAB\x88\r1k\xEC\xF5\x81\xCF\xB2\x8FD\x84x1{\x99h\xD4F\x92\xC3Q\xEEQ\xB5QLl\x99\xD1{#`wQDr\x91\xB4\xCD>9\x8C~\xB9\x02=g\xC3\x04\x00\xF4\e\"\x8C\x9EM\xEA\xB3\x91 N\x87bN\xAA\xE9W\n\xA4Y\x8AU\x9D\xB9\x0F\xF0\xB6\x197\xDF5!\x92W\x9B\xAC\xA2k\xD5\xAFk"
        }
      },
      'blowfish-ctr' => {
        'hmac-sha2-256' => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC07{\xD0\xCE\xF5Wy\"c\x1Ey\xB0-\xBD\xCA~\x8F\x10U\xED\x01\xFF\x95F\xE5\x86\xAD\xC7\x13N\xE8J",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9\xF7F\x99v\xB5o\f9$\x94\x81\e\xF4+\x96H\xFC\xFF=\ts\x82`\x16\e,\xE7\t\x8F\x86t\xC7"
        },
        'hmac-sha2-256-96' => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC07{\xD0\xCE\xF5Wy\"c\x1Ey\xB0",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9\xF7F\x99v\xB5o\f9$\x94\x81\e"
        },
        'hmac-sha2-512' => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0#/\xCF\x00\xE0I\xBC\xF3_\x95U*\xD7z\x81\xCEc\xC3\xBDA\xF2\xD8^J\xBF\xC05oI\xBA\xF2\xEA\x86\xF8h\x8B\xB2\xC89\xC8v\x1F\x04\x12\x80]&\xF5\xC8\xC0\x90D[\xE8\x1E\x95\x89\xEB\xF1\xF6\x9F\xB7\x84\xD5",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9Q\xC92O\x93\xF1\x8E\x9D\x12\x8E\x0E2\xAE\xE3\x8C\xD0\v\xD1\xF6/$\x0F]2\xC2\xE35\x8F\xD4\xA5\x1F\xC1\x95p\xB8\x91c\xC7\xC2u\x8Bb 4#\x82PFI\xF9\xB7l\xFC\xC9\x01\xB2z(\xDD|\xDC\xA46\x96"
        },
        'hmac-sha2-512-96' => {
          false => "\xF7gk6\xB8\xACK\x1D\xC4Ls\xB0{\x0F\xC7\xC4M\xC5>\xF6G8\xD4\xBCu\x152FoJ\xB0\xC0#/\xCF\x00\xE0I\xBC\xF3_\x95U*",
          :standard => "\xF7gk\x0E\xB9\xD0\xD6\x7F\xA5(\x1A\xB4\xFE!\xFB\xEE\x00\xE1\x1F^\x8Bs\xD3\xCEe\rq!8\xFA\xFFB\r\xE9\xFC\xF6\xCA\xBC\x03\xA9Q\xC92O\x93\xF1\x8E\x9D\x12\x8E\x0E2"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xF3cj*\xB0\xA8Cy\xA1.\x0F\xB3y\x04\xDC\xC4*\xACP\x91O \x97\xDB\xEA\xD57~3;\xEB\xCD\xB6\xCDV\xEEp\x93\xF5\v\xB1T\xA6\xD2L=71L]\xE2\xDA\xE0G2\x05",
          :standard => "\x00\x00\x00 \xF2\x1F\xF7H\xD1\xCC*}$\x003\x994 \xFDl\xE6\xE7W\xE3_8\xD4\xBC}\xF2\x8E) Fg\x1D\xAAZ^[\xEF\x17\x1A2\xAAY\xEB\xB0F\x8F Z1Ung\xB7\xBC.\xA2\xE2\x8A\xC1\x17h\xC1\x17\xF2"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\xF3cj*\xB0\xA8Cy\xA1.\x0F\xB3y\x04\xDC\xC4*\xACP\x91O \x97\xDBI\xF9\xEC\xD5\x92\xA4([\xA3\x12:\x1E\x8B_q\x81\x89\xB1\xE1\x13B\xB1\xD1A,\xCA\xFF\xC1\x99\f\xEC\xA0T\xC4\xAE\x1Ed\x0F{B\x85\xD4\xD8\xAA-0\xF6{\xC1\x9C\x95qo+\xA1\x90 `;\xADL\xC5]@",
          :standard => "\x00\x00\x00 \xF2\x1F\xF7H\xD1\xCC*}$\x003\x994 \xFDl\xE6\xE7W\xE3_8\xD4\xBC}\xF2\x8E) Fg\x1D\xF4\xCEUk\a\xF8\xA2V\xFD]\xA98W)\x86\xC6\xAF\xEB\xBB\xBF\xB2\xF8\xF7u\xAD\x90\xB5P\xAA\x195\x93:\x85\xAB1\xD5d9\x99\xD6\xE8\\V\xCC*q\xDB\xD5\x7F|`\x10\xE9yR\x82-\xDA\xE4\xE0K%\x87"
        }
      },
      'aes128-ctr' => {
        'hmac-sha2-256' => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD7{\xD0\xCE\xF5Wy\"c\x1Ey\xB0-\xBD\xCA~\x8F\x10U\xED\x01\xFF\x95F\xE5\x86\xAD\xC7\x13N\xE8J",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15\xFB\x1D\xDC\xE0M\x1AB\xC7\xD4\x9A\x89m'\xE7k\xAB\xF9\xE1\xD6\xAC\xEE\xB3[\xA12\xC2R\xD0\xBC\xF5\xAD\x03"
        },
        'hmac-sha2-256-96' => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD7{\xD0\xCE\xF5Wy\"c\x1Ey\xB0",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15\xFB\x1D\xDC\xE0M\x1AB\xC7\xD4\x9A\x89m"
        },
        'hmac-sha2-512' => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD#/\xCF\x00\xE0I\xBC\xF3_\x95U*\xD7z\x81\xCEc\xC3\xBDA\xF2\xD8^J\xBF\xC05oI\xBA\xF2\xEA\x86\xF8h\x8B\xB2\xC89\xC8v\x1F\x04\x12\x80]&\xF5\xC8\xC0\x90D[\xE8\x1E\x95\x89\xEB\xF1\xF6\x9F\xB7\x84\xD5",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15N\x05f\xBDu\x98\xE4xF\xEC+RSTS\xF0\x9D\x04\xC9$cW\xEFo\"fy\x19\xD1yX\tYK\xE7\xF3kd\a\x12\xC7r\x7F[ \xBC\x0E4\x92\xC0 \x1F\xD8<\xB4\x01^\xA6\xDF\x04\xF5\x9B\x82\xC8"
        },
        'hmac-sha2-512-96' => {
          false => "\xD6\x98\xC1n+6\xCA`s2\x06\xAA\x80\xFA\xF3\xF6\xCA\xF9\xC8[BB\xDC\x9F\xDC$\x88*\xA7\x00\x8E\xFD#/\xCF\x00\xE0I\xBC\xF3_\x95U*",
          :standard => "\xD6\x98\xC1^2JW\x02\x12Vo\xAE\x05\xD4\xCF\xDC\x87\xDD\xE9\xF3\x8E\t\xDB\xED\xCC<\xCBM\xF0\xB0\xC1\x7F\xD7\x17\x931\xBC~\r\xF2\x87\xB89\x9B\x8B\xB3\x8E\x15N\x05f\xBDu\x98\xE4xF\xEC+R"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00 \xDA\x9C\xC0r#2\xC2\x04\x16Pz\xA9\x82\xF1\xE8\xF6\xAD\x90\xA6<JZ\x9F\xF8\x83s{\xC7\xAE\xFB\\B\xCC\xFAD\x95\xC7L\xF1\xB5j)\x06B\xE1\x0F\xEA\x97\x95 <\r1#\x83#\xF8!\xFE\xE9~\x16\xA31",
          :standard => "\x00\x00\x00 \xD3\xE0]\x10BV\xAB\x00\x93~F\x83\xCF\xD5\xC9^a\xDB\xA1NZB\xDC\x9F\xD4\xC34E\xE8\fY \x91\x80\xE49I`\xE6\xED\x96\xA2C\x01\xF5\xB7{\t<\x88d\xDC/#O\x9B\xC2v\x955\x1F\x1D\x8A\x0F"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00 \xDA\x9C\xC0r#2\xC2\x04\x16Pz\xA9\x82\xF1\xE8\xF6\xAD\x90\xA6<JZ\x9F\xF8\x83s{\xC7\xAE\xFB\\B\xD0\xC5k\x1Ad\x979\xDE\xD1SP\xFD\x03\xAF4\xE3\x7F4JY{\x947\x82\xB4\x86h\xAF\xCE/\xA7m\xEE\x8D\xADZ\b\x1A'g\xE2\t\x15\x9E=\x81\xFFSH\xA4\xBC\xA5\xD6\xCF\x9C\xFB@F\xC6\xEB\xDBN\xC7\x82",
          :standard => "\x00\x00\x00 \xD3\xE0]\x10BV\xAB\x00\x93~F\x83\xCF\xD5\xC9^a\xDB\xA1NZB\xDC\x9F\xD4\xC34E\xE8\fY \xCEl\xF3\x95u\xF9\xD2\x17\x83\x98\xC6Q\x91S?\e^\xF6q\xA0M\x92S'\xD7\x1D\x84\x0E]\x82\x8F!U\x85S\xD2*\xB7\xC5\xBD\x00j\xC2@W\x82\xC9\x14\x95c\a\x99\xC6\xA9\xA0q\xD9\xCA\x87\x01zg\x18\v"
        }
      },
      'aes192-ctr' => {
        'hmac-sha2-256' => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x917{\xD0\xCE\xF5Wy\"c\x1Ey\xB0-\xBD\xCA~\x8F\x10U\xED\x01\xFF\x95F\xE5\x86\xAD\xC7\x13N\xE8J",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1\xFB\x1D\xDC\xE0M\x1AB\xC7\xD4\x9A\x89m'\xE7k\xAB\xF9\xE1\xD6\xAC\xEE\xB3[\xA12\xC2R\xD0\xBC\xF5\xAD\x03"
        },
        'hmac-sha2-256-96' => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x917{\xD0\xCE\xF5Wy\"c\x1Ey\xB0",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1\xFB\x1D\xDC\xE0M\x1AB\xC7\xD4\x9A\x89m"
        },
        'hmac-sha2-512' => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91#/\xCF\x00\xE0I\xBC\xF3_\x95U*\xD7z\x81\xCEc\xC3\xBDA\xF2\xD8^J\xBF\xC05oI\xBA\xF2\xEA\x86\xF8h\x8B\xB2\xC89\xC8v\x1F\x04\x12\x80]&\xF5\xC8\xC0\x90D[\xE8\x1E\x95\x89\xEB\xF1\xF6\x9F\xB7\x84\xD5",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1N\x05f\xBDu\x98\xE4xF\xEC+RSTS\xF0\x9D\x04\xC9$cW\xEFo\"fy\x19\xD1yX\tYK\xE7\xF3kd\a\x12\xC7r\x7F[ \xBC\x0E4\x92\xC0 \x1F\xD8<\xB4\x01^\xA6\xDF\x04\xF5\x9B\x82\xC8"
        },
        'hmac-sha2-512-96' => {
          false => "\xA8\x02\xB4-\xFBYo4F\"\xCF\xB8\x92\xF08\xAC\xE8\xECk\xECO\xE7\xF8\x01\xF8\xB0\x9E\x05\xFB\xA7\xA7\x91#/\xCF\x00\xE0I\xBC\xF3_\x95U*",
          :standard => "\xA8\x02\xB4\x1D\xE2%\xF2V'F\xA6\xBC\x17\xDE\x04\x86\xA5\xC8JD\x83\xAC\xFFs\xE8\xA8\xDDb\xAC\x17\xE8\x13\x92V\x9E\x00!\x1F\xD4\x00\x92T\x15\xDE\xA4\xCA\xE9\xC1N\x05f\xBDu\x98\xE4xF\xEC+R"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00 \xA4\x06\xB51\xF3]gP\#@\xB3\xBB\x90\xFB#\xAC\x8F\x85\x05\x8BG\xFF\xBBf\xA7\xE7m\xE8\xF2\\u.l0\x91c\x82\xD9}7\x13\xE1\xAF \xB5\xE8 \xA5\xA5\x1E\x7Fe\x13\x8A\xCEdo\x1A\x10)\xA0\x9DO\xBB",
          :standard => "\x00\x00\x00 \xADz(S\x929\x0ET\xA6n\x8F\x91\xDD\xDF\x02\x04C\xCE\x02\xF9W\xE7\xF8\x01\xF0W\"j\xB4\xABpL\xFB\xEFi?y^&\xBF\xF0#\xDD}\xBFU\xE7\xAA\x83y\xA7M\xAFMJm\xD2\x81\x1C\x9C;\xC0]\x89"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00 \xA4\x06\xB51\xF3]gP\#@\xB3\xBB\x90\xFB#\xAC\x8F\x85\x05\x8BG\xFF\xBBf\xA7\xE7m\xE8\xF2\\u.@\xBDZq\xDDG\xF3\xEC\x9A,~9\xC9m\x19\xAE7\xBB\xAA\\\n\xAE\xCFn)0\xC6n\xA2\xC6\xB2\xD5\xD0N\n\xDDl\xE5\xA0\xE2A\x89\x1F#'\r\xA5\x81t\x81Z\eF\x8E\xEASO\xFE/\xA3\x9A4{\xDF",
          :standard => "\x00\x00\x00 \xADz(S\x929\x0ET\xA6n\x8F\x91\xDD\xDF\x02\x04C\xCE\x02\xF9W\xE7\xF8\x01\xF0W\"j\xB4\xABpLk;\x02(UdO\xBE`\x1F\x9D\xFD=\xE7\xD2\xEF\x80\xD3FC\xDF\xCA\xDD>r\x0Ev'\xFE9AK\xA3(\x0FT\n\x19M\\\xD8\xA1\x88\x87+^\x92\xC2\xF1\x94\xBB\xFD:\x04dC\xAE\x1E\xD5'jP\xE6\x17"
        }
      },
      'aes256-ctr' => {
        'hmac-sha2-256' => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r7{\xD0\xCE\xF5Wy\"c\x1Ey\xB0-\xBD\xCA~\x8F\x10U\xED\x01\xFF\x95F\xE5\x86\xAD\xC7\x13N\xE8J",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\n\xFB\x1D\xDC\xE0M\x1AB\xC7\xD4\x9A\x89m'\xE7k\xAB\xF9\xE1\xD6\xAC\xEE\xB3[\xA12\xC2R\xD0\xBC\xF5\xAD\x03"
        },
        'hmac-sha2-256-96' => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r7{\xD0\xCE\xF5Wy\"c\x1Ey\xB0",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\n\xFB\x1D\xDC\xE0M\x1AB\xC7\xD4\x9A\x89m"
        },
        'hmac-sha2-512' => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r#/\xCF\x00\xE0I\xBC\xF3_\x95U*\xD7z\x81\xCEc\xC3\xBDA\xF2\xD8^J\xBF\xC05oI\xBA\xF2\xEA\x86\xF8h\x8B\xB2\xC89\xC8v\x1F\x04\x12\x80]&\xF5\xC8\xC0\x90D[\xE8\x1E\x95\x89\xEB\xF1\xF6\x9F\xB7\x84\xD5",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\nN\x05f\xBDu\x98\xE4xF\xEC+RSTS\xF0\x9D\x04\xC9$cW\xEFo\"fy\x19\xD1yX\tYK\xE7\xF3kd\a\x12\xC7r\x7F[ \xBC\x0E4\x92\xC0 \x1F\xD8<\xB4\x01^\xA6\xDF\x04\xF5\x9B\x82\xC8"
        },
        'hmac-sha2-512-96' => {
          false => "M\x1DcA\r]\\\x95?&\xE3D[\xCC1\x9B\xE0\xAF\x96\xA8\x86Y\xBD\x16\xE5xR%u\xC9(\r#/\xCF\x00\xE0I\xBC\xF3_\x95U*",
          :standard => "M\x1Dcq\x14!\xC1\xF7^B\x8A@\xDE\xE2\r\xB1\xAD\x8B\xB7\x00J\x12\xBAd\xF5`\x11B\"yg\x8F\x9F\xAB\xC8 d\xB4\xE7^w\xC4\x89\a\x17\x15\x82\nN\x05f\xBDu\x98\xE4xF\xEC+R"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00 A\x19b]\x05YT\xF1ZD\x9FGY\xC7*\x9B\x87\xC6\xF8\xCF\x8EA\xFEq\xBA/\xA1\xC8|2\xFA\xB2\xB1W\xD4\xA8\xEF\xC8~/>?\xF7f!(\x1C\xB7\x1C\x9C\xA9\xC2\xE4\xEF\x88k\e\x8A\xC4/QM\x84E",
          :standard => "\x00\x00\x00 He\xFF?d==\xF5\xDFj\xA3m\x14\xE3\v3K\x8D\xFF\xBD\x9EY\xBD\x16\xED\x9F\xEEJ:\xC5\xFF\xD0\x81\xFC\xA4\x87\xF3\x06x\xFE\xCDV*%\x13\xAA|\xA8\xE3\xB8^`vl\xFF\x02\xF9\xEC\x02\x8A\xFFt\xFC\x03"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00 A\x19b]\x05YT\xF1ZD\x9FGY\xC7*\x9B\x87\xC6\xF8\xCF\x8EA\xFEq\xBA/\xA1\xC8|2\xFA\xB2\x86x\r\x88Q-B\x03\xD5\x14\x8D\x98\xA3}&\x98va\xD9UZs\x82|\xDA{\xAD\x96\x88\x05%s\xB4*_\xBFWR\a\x90\xD9P\x81IY\xAE\x88|\x88\xC1k\x16\xDF\xDFPA\xBB\x13Dk\x84\xBBe1",
          :standard => "\x00\x00\x00 He\xFF?d==\xF5\xDFj\xA3m\x14\xE3\v3K\x8D\xFF\xBD\x9EY\xBD\x16\xED\x9F\xEEJ:\xC5\xFF\xD0\xB4\xAE\x8A\x86\xE6\xAE\xF3\xD8\xD8\xB2\x1Dazu$\x01nc\aYh\xBA\x15\x83\xE20\x900\\mX\x96\xF22\xEBJa\x96>\xED\x0E\x17`m\e\x97@\xF7Y+\xC8\x98\v\x17I\xC4\x86s\xCF\xB4j\xDEV0"
        }
      },
      'cast128-ctr' => {
        'hmac-sha2-256' => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC77{\xD0\xCE\xF5Wy\"c\x1Ey\xB0-\xBD\xCA~\x8F\x10U\xED\x01\xFF\x95F\xE5\x86\xAD\xC7\x13N\xE8J",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA\xF7F\x99v\xB5o\f9$\x94\x81\e\xF4+\x96H\xFC\xFF=\ts\x82`\x16\e,\xE7\t\x8F\x86t\xC7"
        },
        'hmac-sha2-256-96' => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC77{\xD0\xCE\xF5Wy\"c\x1Ey\xB0",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEA\xF7F\x99v\xB5o\f9$\x94\x81\e"
        },
        'hmac-sha2-512' => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7#/\xCF\x00\xE0I\xBC\xF3_\x95U*\xD7z\x81\xCEc\xC3\xBDA\xF2\xD8^J\xBF\xC05oI\xBA\xF2\xEA\x86\xF8h\x8B\xB2\xC89\xC8v\x1F\x04\x12\x80]&\xF5\xC8\xC0\x90D[\xE8\x1E\x95\x89\xEB\xF1\xF6\x9F\xB7\x84\xD5",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEAQ\xC92O\x93\xF1\x8E\x9D\x12\x8E\x0E2\xAE\xE3\x8C\xD0\v\xD1\xF6/$\x0F]2\xC2\xE35\x8F\xD4\xA5\x1F\xC1\x95p\xB8\x91c\xC7\xC2u\x8Bb 4#\x82PFI\xF9\xB7l\xFC\xC9\x01\xB2z(\xDD|\xDC\xA46\x96"
        },
        'hmac-sha2-512-96' => {
          false => "\x10\xA0cJ6W\xC9\xC7\x02\xF8\xCD\xE31\xF9\xE7n\x0Fj\x7F\x99\x8A\f\x84\x80\x80\xE8p\x9C\x14\x83\x1C\xC7#/\xCF\x00\xE0I\xBC\xF3_\x95U*",
          :standard => "\x10\xA0cr7+T\xA5c\x9C\xA4\xE7\xB4\xD7\xDBDBN^1FG\x83\xF2\x90\xF03\xFBC3SE\xF7x;q\x89\xA80\xEAQ\xC92O\x93\xF1\x8E\x9D\x12\x8E\x0E2"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\x14\xA4bV>S\xC1\xA3g\x9A\xB1\xE03\xF2\xFCnh\x03\x11\xFE\x82\x14\xC7\xE7\xF3E\x16\e\xF9\x9FH;\x83\xF5G\xAA\xCE\x94\x1C\x19\xB9\x12\xC0\xB4\xBB\xC6\xA1A\xE8\xFA\x03[\x8D<\xEB\xBE",
          :standard => "\x00\x00\x00 \x15\xD8\xFF4_7\xA8\xA7\xE2\xB4\x8D\xCA~\xD6\xDD\xC6\xA4H\x16\x8C\x92\f\x84\x80\x88\x0F\xCC\xF3[\x8F\xCB\x1A\xD2Q\xA8\xA0\x990tw\x89*\xB4\xA1\xB9\x9A\xF2\xBD9v\"st\xB7:S5o\xD0\xA1\xD5\xA5\xC3\x83"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\x14\xA4bV>S\xC1\xA3g\x9A\xB1\xE03\xF2\xFCnh\x03\x11\xFE\x82\x14\xC7\xE7U\f\xDF\xD4(\xEE\xEE\xEE\x1D%\xDC\xE9n\xA6C\xB7\xB8!K\x90\xD2%\r\xB7\xAA\t\xE1\xA5\x12#\x93\x95m\xD8GY\xF4\xC9\xCC\xF8\x19(6\xD5\xE3\x8F.\xC9\xBFE\xAF\x8C\xF2\xA9\xD96v[zf\x02CI`",
          :standard => "\x00\x00\x00 \x15\xD8\xFF4_7\xA8\xA7\xE2\xB4\x8D\xCA~\xD6\xDD\xC6\xA4H\x16\x8C\x92\f\x84\x80\x88\x0F\xCC\xF3[\x8F\xCB\x1A\xE9\xC8\xAC\x85n\xDE\xF6H\xF0\xFAE_\xE43I\xCE\xC0\x8A\xC2\xD0+o\x1E\xFB\xCF\xFC\x8E\tI\xFFLlV\xEAP\xE8h\xEF\xF0p!p\x83B'\xFA\xF7wk\xA0\xD4\xB9x\xC6h\xAC\xD9\x94\xC1\x0E\xD44.\xFB"
        }
      },
      'none' => {
        'hmac-sha2-256' => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\2127{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^\367F\231v\265o\f9$\224\201\e\364+\226H\374\377=\ts\202`\026\e,\347\t\217\206t\307"
        },
        'hmac-sha2-256-96' => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\2127{\320\316\365Wy\"c\036y\260",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^\367F\231v\265o\f9$\224\201\e"
        },
        'hmac-sha2-512' => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^Q\3112O\223\361\216\235\022\216\0162\256\343\214\320\v\321\366/$\017]2\302\3435\217\324\245\037\301\225p\270\221c\307\302u\213b 4#\202PFI\371\267l\374\311\001\262z(\335|\334\2446\226"
        },
        'hmac-sha2-512-96' => {
          false => "\000\000\000\034\b\004\001\000\000\000\tdebugging\000\000\000\000\b\030CgWO\260\212#/\317\000\340I\274\363_\225U*",
          :standard => "\000\000\000$\tx\234bad``\340LIM*MO\317\314K\ar\030\000\000\000\000\377\377\b\030CgWO\260\212^Q\3112O\223\361\216\235\022\216\0162"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\x04\x04\x01\x00\x00\x00\tdebugging\x00\x00\x00\x00\b\x18Cg:\xCA\xDDb\x1D\xA9'?\xBB\xB1\x86\xBB\x98\xD3\x1E4\xDA;\x93\xDF\xBFz\x8D\x98\xDF\xFB PZ\xD9o\xF8",
          :standard => "\x00\x00\x00 \x05x\x9Cbad``\xE0LIM*MO\xCF\xCCK\ar\x18\x00\x00\x00\x00\xFF\xFF\b\x18CgW\x80-\xA99B\x81\xFE\xF2\v*\x00\xF7\xB3o\xBCQ\xAEWj\xC9\x14\x197-8tk/\x9E\xAF\x00\xAB"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00\x18\x04\x04\x01\x00\x00\x00\tdebugging\x00\x00\x00\x00\b\x18Cg\x8D\x98\x9D\xCA`\xC7\x13| \xBE\xC4@N\xCE\x15\xD8\x0E\x03\xE3\xEC\x1AB\xD7\xC0\xA2j=\x8C\x17\xFA,\xAEY\xDD\xF7\xDC\bNTX\xEF\xF1\x80\x1A\x81h\xC7:\xDD\x9B\xC7R\xB4\x93\xA8#\x967f\xF7\xE0\x84\xCF\x9F",
          :standard => "\x00\x00\x00 \x05x\x9Cbad``\xE0LIM*MO\xCF\xCCK\ar\x18\x00\x00\x00\x00\xFF\xFF\b\x18CgW\xBADS\xA9\xF0I\x91\xFF< /\x1E\e\xC4v\x9B\x11\x9E\xEFiW[*d\xA26\xEA\xFB\xD5*\xC8\x9B\x9A\xAC.h:\xED\xA8R\xAD\xFC\x85@\xC3\x89\x8E,\x01*O\xF2\xFE\r\xCF\xA4\xA5\xAB\x03k\xC8\x9E])"
        }
      },
      'rijndael-cbc@lysator.liu.se' => {
        'hmac-sha2-256' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\3407{\320\316\365Wy\"c\036y\260-\275\312~\217\020U\355\001\377\225F\345\206\255\307\023N\350J",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\373\035\334\340M\032B\307\324\232\211m'\347k\253\371\341\326\254\356\263[\2412\302R\320\274\365\255\003"
        },
        'hmac-sha2-256-96' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\3407{\320\316\365Wy\"c\036y\260",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365\373\035\334\340M\032B\307\324\232\211m"
        },
        'hmac-sha2-512' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340#/\317\000\340I\274\363_\225U*\327z\201\316c\303\275A\362\330^J\277\3005oI\272\362\352\206\370h\213\262\3109\310v\037\004\022\200]&\365\310\300\220D[\350\036\225\211\353\361\366\237\267\204\325",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365N\005f\275u\230\344xF\354+RSTS\360\235\004\311$cW\357o\"fy\031\321yX\tYK\347\363kd\a\022\307r\177[ \274\0164\222\300 \037\330<\264\001^\246\337\004\365\233\202\310"
        },
        'hmac-sha2-512-96' => {
          false => "\266\001oG(\201s\255[\202j\031-\354\353]\022\374\367j2\257\b#\273r\275\341\232\264\255\340#/\317\000\340I\274\363_\225U*",
          :standard => "\251!O/_\253\321\217e\225\202\202W\261p\r\357\357\375\231\264Y,nZ/\366\225G\256\3000\036\223\237\353\265vG\231\215cvY\236%\315\365N\005f\275u\230\344xF\354+R"
        },
        'hmac-sha2-256-etm@openssh.com' => {
          false => "\x00\x00\x00 \xDF'\xE2\xE7\xF6.\x92\x9F\xBA)N\xFE\xA0\xCC\x9A\x9Ai{\xB5\r\f\x18\xFA\xA9\x89\x9B\xD3\xF0zXK^\xFF\xB9\x14\xF1?\x0Ez\xF5\x8A\t~x\xCC\xFFj\x15\xE8\"\xA1dUd\xA4\xA5?\xF0\x1E\xE9\x82\xE2R\a",
          :standard => "\x00\x00\x00 1\xFC\xCAD\x0E\x97\x7F\xC51\xB0\b\xE1\xE7\xAC\x90\x9E\xCD\xB2\x88\x84d*\xD5E\xE1\x15\xC9\xBE\xCB\x8D\x14^\x9A\xC4v\xAA\xA7\x19L\x0E\xCBX;\xEDh\xDC\xCD\xD0\xB4#>\x8B\x7F\xB6\x97U\x84\x9CB\x84\xB1]\x1Co"
        },
        'hmac-sha2-512-etm@openssh.com' => {
          false => "\x00\x00\x00 \xDF'\xE2\xE7\xF6.\x92\x9F\xBA)N\xFE\xA0\xCC\x9A\x9Ai{\xB5\r\f\x18\xFA\xA9\x89\x9B\xD3\xF0zXK^>\xE2\xDE\x95]\xD4\f%gBo3\x95\xD7\xFBF\xD8\xC5\x18R\x10\xB0\xA6i\xB8\ej\xAA}?\xF8\xA7\xB2K\x9E\xE3\b\xA5.D\x94\x04,\xB1\xFA\x92\xAA\xA9`\x95\x19\xC7P\x92r<\xCB\x93\xD9\xD8Nu\x89\b",
          :standard => "\x00\x00\x00 1\xFC\xCAD\x0E\x97\x7F\xC51\xB0\b\xE1\xE7\xAC\x90\x9E\xCD\xB2\x88\x84d*\xD5E\xE1\x15\xC9\xBE\xCB\x8D\x14^\xF8\xD2x\x817\x7F#b\xEC\x96\xB9\xE2pG\x9BI\bQ\xC0\xA8\xB6$\xA8]\x05?e\xE5\x86S\x0Fw\xA4Q\xAFW\xFE>\x9B7:\eF\n\xDF\xB1\x85M\xA5N\xCC^\xC9\xA6\xCDp\xBA\x13>\xB9\xEB~\x87\xEB"
        }
      }
    }
    sha2_packets.each do |key, val|
      PACKETS[key].merge!(val)
    end

    ciphers = Net::SSH::Transport::CipherFactory::SSH_TO_OSSL.keys + Net::SSH::Transport::CipherFactory::SSH_TO_CLASS.keys
    hmacs = Net::SSH::Transport::HMAC::MAP.keys + ["implicit"]
    implicit_ciphers = %w[chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com]

    ciphers.each do |cipher_name|
      unless Net::SSH::Transport::CipherFactory.supported?(cipher_name) && PACKETS.key?(cipher_name)
        puts "Skipping packet stream test for #{cipher_name}"
        next
      end

      # JRuby Zlib implementation (1.4 & 1.5) does not have byte-to-byte compatibility with MRI's.
      # skip these 80 or more tests under JRuby.
      if defined?(JRUBY_VERSION)
        puts "Skipping zlib tests for JRuby"
        next
      end

      hmacs.each do |hmac_name|
        [false, :standard].each do |compress|
          next if (hmac_name != "implicit" && implicit_ciphers.include?(cipher_name)) ||
                  (hmac_name == "implicit" && !implicit_ciphers.include?(cipher_name))

          cipher_method_name = cipher_name.gsub(/\W/, "_")
          hmac_method_name   = hmac_name.gsub(/\W/, "_")

          define_method("test_next_packet_with_#{cipher_method_name}_and_#{hmac_method_name}_and_#{compress}_compression") do
            opts = { shared: "123", hash: "^&*", digester: OpenSSL::Digest::SHA1 }
            key = "ABC"
            cipher = Net::SSH::Transport::CipherFactory.get(cipher_name, opts.merge(key: key, decrypt: true, iv: "abc"))
            hmac =
              if cipher.implicit_mac?
                cipher.implicit_mac
              else
                Net::SSH::Transport::HMAC.get(hmac_name, "{}|", opts)
              end

            cipher.nonce = ["000000000000000000000031"].pack('H*') if hmac.respond_to?(:aead) && hmac.aead

            stream.server.set cipher: cipher, hmac: hmac, compression: compress
            stream.stubs(:recv).returns(PACKETS[cipher_name][hmac_name][compress])
            IO.stubs(:select).returns([[stream]])
            packet = stream.next_packet(:nonblock)
            assert_not_nil packet
            assert_equal DEBUG, packet.type
            assert packet[:always_display]
            assert_equal "debugging", packet[:message]
            assert_equal "", packet[:language]
            stream.stubs(:pid).returns(nil)
            stream.cleanup
          end

          define_method("test_enqueue_packet_with_#{cipher_method_name}_and_#{hmac_method_name}_and_#{compress}_compression") do
            if compress == :standard && Zlib.zlib_version.include?("zlib-ng")
              puts "Skipping zlib #{cipher_method_name} and #{hmac_method_name} and #{compress} compression test for zlib-ng"
              next
            end

            opts = { shared: "123", digester: OpenSSL::Digest::SHA1, hash: "^&*" }
            key = "ABC"
            cipher = Net::SSH::Transport::CipherFactory.get(cipher_name, opts.merge(key: key, iv: "abc", encrypt: true))
            hmac =
              if cipher.implicit_mac?
                cipher.implicit_mac
              else
                Net::SSH::Transport::HMAC.get(hmac_name, "{}|", opts)
              end

            cipher.nonce = ["000000000000000000000031"].pack('H*') if hmac.respond_to?(:aead) && hmac.aead

            srand(100)
            stream.client.set cipher: cipher, hmac: hmac, compression: compress
            stream.enqueue_packet(ssh_packet)
            assert_equal PACKETS[cipher_name][hmac_name][compress], stream.write_buffer
            stream.stubs(:pid).returns(nil)
            stream.cleanup
          end
        end
      end
    end

    private

    def stream
      @stream ||= begin
        stream = mock("packet_stream")
        stream.extend(Net::SSH::Transport::PacketStream)
        stream
      end
    end

    def ssh_packet
      Net::SSH::Buffer.from(:byte, DEBUG, :bool, true, :string, "debugging", :string, "")
    end

    def packet
      @packet ||= begin
        data = ssh_packet
        length = data.length + 4 + 1 # length + padding length
        padding = stream.server.cipher.block_size - (length % stream.server.cipher.block_size)
        padding += stream.server.cipher.block_size if padding < 4
        Net::SSH::Buffer.from(:long, length + padding - 4, :byte, padding, :raw, data, :raw, "\0" * padding).to_s
      end
    end
  end
end
