# encoding: ASCII-8BIT

require 'common'
require 'net/ssh/transport/cipher_factory'

module Transport
  class TestCipherFactory < NetSSHTest
    def self.if_supported?(name)
      yield if Net::SSH::Transport::CipherFactory.supported?(name)
    end

    def test_lengths_for_none
      assert_equal [0, 0], factory.get_lengths("none")
      assert_equal [0, 0], factory.get_lengths("bogus")
    end

    def test_lengths_for_blowfish_cbc
      assert_equal [16, 8], factory.get_lengths("blowfish-cbc")
    end

    if_supported?("idea-cbc") do
      def test_lengths_for_idea_cbc
        assert_equal [16, 8], factory.get_lengths("idea-cbc")
      end
    end

    def test_lengths_for_rijndael_cbc
      assert_equal [32, 16], factory.get_lengths("rijndael-cbc@lysator.liu.se")
    end

    def test_lengths_for_cast128_cbc
      assert_equal [16, 8], factory.get_lengths("cast128-cbc")
    end

    def test_lengths_for_3des_cbc
      assert_equal [24, 8], factory.get_lengths("3des-cbc")
    end

    def test_lengths_for_aes128_cbc
      assert_equal [16, 16], factory.get_lengths("aes128-cbc")
    end

    def test_lengths_for_aes192_cbc
      assert_equal [24, 16], factory.get_lengths("aes192-cbc")
    end

    def test_lengths_for_aes256_cbc
      assert_equal [32, 16], factory.get_lengths("aes256-cbc")
    end

    def test_lengths_for_3des_ctr
      assert_equal [24, 8], factory.get_lengths("3des-ctr")
    end

    def test_lengths_for_aes128_ctr
      assert_equal [16, 16], factory.get_lengths("aes128-ctr")
    end

    def test_lengths_for_aes192_ctr
      assert_equal [24, 16], factory.get_lengths("aes192-ctr")
    end

    def test_lengths_for_aes256_ctr
      assert_equal [32, 16], factory.get_lengths("aes256-ctr")
    end

    def test_lengths_for_blowfish_ctr
      assert_equal [16, 8], factory.get_lengths("blowfish-ctr")
    end

    def test_lengths_for_cast128_ctr
      assert_equal [16, 8], factory.get_lengths("cast128-ctr")
    end

    BLOWFISH_CBC = "\210\021\200\315\240_\026$\352\204g\233\244\242x\332e\370\001\327\224Nv@9_\323\037\252kb\037\036\237\375]\343/y\037\237\312Q\f7]\347Y\005\275%\377\0010$G\272\250B\265Nd\375\342\372\025r6}+Y\213y\n\237\267\\\374^\346BdJ$\353\220Ik\023<\236&H\277=\225"

    def test_blowfish_cbc_for_encryption
      assert_equal BLOWFISH_CBC, encrypt("blowfish-cbc")
    end

    def test_blowfish_cbc_for_decryption
      assert_equal TEXT, decrypt("blowfish-cbc", BLOWFISH_CBC)
    end

    if_supported?("idea-cbc") do
      IDEA_CBC = "W\234\017G\231\b\357\370H\b\256U]\343M\031k\233]~\023C\363\263\177\262-\261\341$\022\376mv\217\322\b\2763\270H\306\035\343z\313\312\3531\351\t\201\302U\022\360\300\354ul7$z\320O]\360g\024\305\005`V\005\335A\351\312\270c\320D\232\eQH1\340\265\2118\031g*\303v"

      def test_idea_cbc_for_encryption
        assert_equal IDEA_CBC, encrypt("idea-cbc")
      end

      def test_idea_cbc_for_decryption
        assert_equal TEXT, decrypt("idea-cbc", IDEA_CBC)
      end
    end

    RIJNDAEL = "$\253\271\255\005Z\354\336&\312\324\221\233\307Mj\315\360\310Fk\241EfN\037\231\213\361{'\310\204\347I\343\271\005\240`\325;\034\346uM>#\241\231C`\374\261\vo\226;Z\302:\b\250\366T\330\\#V\330\340\226\363\374!\bm\266\232\207!\232\347\340\t\307\370\356z\236\343=v\210\206y"

    def test_rijndael_cbc_for_encryption
      assert_equal RIJNDAEL, encrypt("rijndael-cbc@lysator.liu.se")
    end

    def test_rijndael_cbc_for_decryption
      assert_equal TEXT, decrypt("rijndael-cbc@lysator.liu.se", RIJNDAEL)
    end

    CAST128_CBC = "qW\302\331\333P\223t[9 ~(sg\322\271\227\272\022I\223\373p\255>k\326\314\260\2003\236C_W\211\227\373\205>\351\334\322\227\223\e\236\202Ii\032!P\214\035:\017\360h7D\371v\210\264\317\236a\262w1\2772\023\036\331\227\240:\f/X\351\324I\t[x\350\323E\2301\016m"

    def test_cast128_cbc_for_encryption
      assert_equal CAST128_CBC, encrypt("cast128-cbc")
    end

    def test_cast128_cbc_for_decryption
      assert_equal TEXT, decrypt("cast128-cbc", CAST128_CBC)
    end

    TRIPLE_DES_CBC = "\322\252\216D\303Q\375gg\367A{\177\313\3436\272\353%\223K?\257\206|\r&\353/%\340\336 \203E8rY\206\234\004\274\267\031\233T/{\"\227/B!i?[qGaw\306T\206\223\213n \212\032\244%]@\355\250\334\312\265E\251\017\361\270\357\230\274KP&^\031r+r%\370"

    def test_3des_cbc_for_encryption
      assert_equal TRIPLE_DES_CBC, encrypt("3des-cbc")
    end

    def test_3des_cbc_for_decryption
      assert_equal TEXT, decrypt("3des-cbc", TRIPLE_DES_CBC)
    end

    AES128_CBC = "k\026\350B\366-k\224\313\3277}B\035\004\200\035\r\233\024$\205\261\231Q\2214r\245\250\360\315\237\266hg\262C&+\321\346Pf\267v\376I\215P\327\345-\232&HK\375\326_\030<\a\276\212\303g\342C\242O\233\260\006\001a&V\345`\\T\e\236.\207\223l\233ri^\v\252\363\245"

    def test_aes128_cbc_for_encryption
      assert_equal AES128_CBC, encrypt("aes128-cbc")
    end

    def test_aes128_cbc_for_decryption
      assert_equal TEXT, decrypt("aes128-cbc", AES128_CBC)
    end

    AES192_CBC = "\256\017)x\270\213\336\303L\003f\235'jQ\3231k9\225\267\242\364C4\370\224\201\302~\217I\202\374\2167='\272\037\225\223\177Y\r\212\376(\275\n\3553\377\177\252C\254\236\016MA\274Z@H\331<\rL\317\205\323[\305X8\376\237=\374\352bH9\244\0231\353\204\352p\226\326~J\242"

    def test_aes192_cbc_for_encryption
      assert_equal AES192_CBC, encrypt("aes192-cbc")
    end

    def test_aes192_cbc_for_decryption
      assert_equal TEXT, decrypt("aes192-cbc", AES192_CBC)
    end

    AES256_CBC = "$\253\271\255\005Z\354\336&\312\324\221\233\307Mj\315\360\310Fk\241EfN\037\231\213\361{'\310\204\347I\343\271\005\240`\325;\034\346uM>#\241\231C`\374\261\vo\226;Z\302:\b\250\366T\330\\#V\330\340\226\363\374!\bm\266\232\207!\232\347\340\t\307\370\356z\236\343=v\210\206y"

    def test_aes256_cbc_for_encryption
      assert_equal AES256_CBC, encrypt("aes256-cbc")
    end

    def test_aes256_cbc_for_decryption
      assert_equal TEXT, decrypt("aes256-cbc", AES256_CBC)
    end

    BLOWFISH_CTR = "\xF5\xA6\x1E{\x8F(\x85G\xFAh\xDB\x19\xDC\xDF\xA2\x9A\x99\xDD5\xFF\xEE\x8BE\xE6\xB5\x92\x82\xE80\x91\x11`\xEF\x10\xED\xE9\xD3\vG\x0E\xAF\xB2K\t\xA4\xA6\x05\xD1\x17\x0Fl\r@E\x8DJ\e\xE63\x04\xB5\x05\x99Y\xCC\xFBb\x8FK+\x8C1v\xE4N\b?B\x06Rz\xA6\xB6N/b\xCE}\x83\x8DY\xD7\x92qU\x0F"

    def test_blowfish_ctr_for_encryption
      assert_equal BLOWFISH_CTR, encrypt("blowfish-ctr")
    end

    def test_blowfish_ctr_for_decryption
      assert_equal TEXT, decrypt("blowfish-ctr", BLOWFISH_CTR)
    end

    CAST128_CTR = "\xB5\xBB\xC3h\x80\x90`{\xD7I\x03\xE9\x80\xC4\xC4U\xE3@\xF1\xE9\xEFX\xDB6\xEE,\x8E\xC2\xE8\x89\x17\xBArf\x81\r\x96\xDC\xB1_'\x83hs\t7\xB8@\x17\xAA\xD9;\xE8\x8E\x94\xBD\xFF\xA4K\xA4\xFA\x8F-\xCD\bO\xD9I`\xE5\xC9H\x99\x14\xC5K\xC8\xEF\xEA#\x1D\xE5\x13O\xE1^P\xDC\x1C^qm\v|c@"

    def test_cast128_ctr_for_encryption
      assert_equal CAST128_CTR, encrypt("cast128-ctr")
    end

    def test_cast128_ctr_for_decryption
      assert_equal TEXT, decrypt("cast128-ctr", CAST128_CTR)
    end

    TRIPLE_DES_CTR = "\x90\xCD\b\xD2\xF1\x15:\x98\xF4sJ\xF0\xC9\xAA\xC5\xE3\xB4\xCFq\x93\xBAB\xF9v\xE1\xE7\x8B<\xBC\x97R\xDF?kK~Nw\xF3\x92`\x90]\xD9\xEF\x16\xC85V\x03C\xE9\x14\xF0\x86\xEB\x19\x85\x82\xF6\x16gz\x9B`\xB1\xCE\x80&?\xC8\xBD\xBC+\x91/)\xA5x\xBB\xCF\x06\x15#\e\xB3\xBD\x9B\x1F\xA7\xE2\xC7\xA3\xFC\x06\xC8"

    def test_3des_ctr_for_encryption
      if defined?(JRUBY_VERSION)
        # on JRuby, this test fails due to JRUBY-6558
        puts "Skipping 3des-ctr tests for JRuby"
      else
        assert_equal TRIPLE_DES_CTR, encrypt("3des-ctr")
      end
    end

    def test_3des_ctr_for_decryption
      if defined?(JRUBY_VERSION)
        # on JRuby, this test fails due to JRUBY-6558
        puts "Skipping 3des-ctr tests for JRuby"
      else
        assert_equal TEXT, decrypt("3des-ctr", TRIPLE_DES_CTR)
      end
    end

    AES128_CTR = "\x9D\xC7]R\x89\x01\xC4\x14\x00\xE7\xCEc`\x80\v\xC7\xF7\xBD\xD5#d\f\xC9\xB0\xDE\xA6\x8Aq\x10p\x8F\xBC\xFF\x8B\xB4\xC5\xB3\xF7,\xF7eO\x06Q]\x0F\x05\x86\xEC\xA6\xC8\x12\xE9\xC4\x9D0\xD3\x9AL\x192\xAA\xDFu\x0E\xECz\x7F~g\xCA\xEA\xBA\x80,\x83V\x10\xF6/\x04\xD2\x8A\x94\x94\xA9T>~\xD2\r\xE6\x0E\xA0q\xEF"
    AES128_CTR2 = "\xA5\xAA\xE3\xEC\xA7\xCCc\xFA~\x01\r\xD87\xE6\"\n6\x05\xD1\x9B\xC8_o\xD1i\xF6t\xD7[\xE5\x8B%>]\xD6\xC4<\x1DBd\xA9\x02\x9C\xEB\x89#\x955\xD6\x0F\xD0\x03\xF9\xC6\xD7\xB0@\e\\\xAB\xC0\xA9\xFB\x91\#{w\xADL\xF6'(\xCC\x14\xA2A\x16\xC1\x9C'\xD1\xBA'i\x88\x80\xF1\xA7E\x82\xA8\xC7@\xBA\a\xEA"

    def test_aes128_ctr_for_encryption
      assert_equal AES128_CTR, encrypt("aes128-ctr")
    end

    def test_aes128_ctr_for_encryption2
      assert_equal [AES128_CTR, AES128_CTR2], encrypt2("aes128-ctr")
    end

    def test_aes128_ctr_for_decryption2
      assert_equal [TEXT, TEXT2], decrypt2("aes128-ctr", [AES128_CTR, AES128_CTR2])
    end

    def test_aes128_ctr_for_decryption
      assert_equal TEXT, decrypt("aes128-ctr", AES128_CTR)
    end

    AES192_CTR = "\xE2\xE7\x1FJ\xE5\xB09\xE1\xB7/\xB3\x95\xF2S\xCE\x8C\x93\x14mFY\x88*\xCE\b\xA6\x87W\xD7\xEC/\xC9\xB6\x9Ba\a\x8E\x89-\xD7\xB2j\a\xB3\a\x92f\"\x96\x8D\xBF\x01\t\xB8Y\xF3\x92\x01\xCC7\xB6w\xF9\"=u:\xA1\xD5*\n\x9E\xC7p\xDC\x11\a\x1C\x88y\xE8\x87`\xA6[fF\x9B\xACv\xA6\xDA1|#F"

    def test_aes192_ctr_for_encryption
      assert_equal AES192_CTR, encrypt("aes192-ctr")
    end

    def test_aes192_ctr_for_decryption
      assert_equal TEXT, decrypt("aes192-ctr", AES192_CTR)
    end

    AES256_CTR = "2\xB8\xE6\xC9\x95\xB4\x05\xD2\xC7+\x7F\x88\xEB\xD4\xA0\b\"\xBF\x9E\x85t\x19,\e\x90\x11\x04b\xC7\xEE$\xDE\xE6\xC5@G\xFEm\xE1u\x9B\au\xAF\xB5\xB8\x857\x87\x139u\xAC\x1A\xAB\fh\x8FiW~\xB8:\xA4\xA0#~\xC4\x89\xBA5#:\xFC\xC8\xE3\x9B\xF0A2\x87\x980\xD1\xE3\xBC'\xBE\x1E\n\x1A*B\x06\xF3\xCC"
    AES256_CTR2 = "\x13\xBF}\x93\xC3\xFCkw[\\\x8A\xDA\x9F\x85e3AH!\x19\xD9S(+x]B\x1A\x85):\x1Ce\xB1\xD1\x9F^\x8D\\\xFA\xFE\xC6\x9FDkm=?>.\x93\xA6O\x80\xB5o\xBE\xB5\\82\xEEWi\xFC<\xA7\xB6g\xBD\xF1\xA6\xAA\xE7\xD3_&N\xC9[K8\xE61L\xD1\xC0\xC8\x02\b\xE7\xF1!\xA5\x04\xCA"

    def test_aes256_ctr_for_encryption
      assert_equal AES256_CTR, encrypt("aes256-ctr")
    end

    def test_aes256_ctr_for_encryption2
      assert_equal [AES256_CTR, AES256_CTR2], encrypt2("aes256-ctr")
    end

    def test_aes256_ctr_for_decryption
      assert_equal TEXT, decrypt("aes256-ctr", AES256_CTR)
    end

    AES256_GCM = "\xA0\xDC#-\xB4\x010+\aP\x85 \x0E\xD0!\x8D\xB3\xA9\x8A\x92K\x0F\x82?*\xCA[\f\eJ{\x97\a\xB1Z\f\x93\x16\xEF%\xCA\xAC\xE4\x0E\xF6Y\xA9H\xC2\"zsg\xD3\xF69\xF9\xE3-\xCF\t\x1A\xA6\xA4U\xF5w\x89?k\x04\xE2I\xD9\xC4\x03\xD9\x9D~\xF5\xF9\xDE\x04\xC3\xF8\xCC\x9B\xB8&2\xF8B+e\x92\v"
    AES256_GCM2 = "\xA2d\xE2v\xB6\xC7\xA6}\xAE\xBC'\xEBe\xE2*l\xC1\xFF\x96\xF0\\:\xA4\xCF\xAD\a\xAFW\x90\x1C4\x7F7E\xF4\xDF \xB5\x1C\xB6K\x18s^\f\x96S#7F\x99\xCAP_\x98\xFC\x13\xF5c-\xF2@6\x9Cg\xE8\xF3Q%\xC6\xF5K\xCE\xD7\xB9\xDF\xC5\x04K\xD1\xF2\xB0M\xF0\x9F(\xD8\x05u\xE8\xBA\xAA\x81\xF0nD"

    def test_aes256_gcm_for_encryption
      assert_equal AES256_GCM, encrypt("aes256-gcm@openssh.com")
    end

    def test_aes256_gcm_for_encryption2
      assert_equal [AES256_GCM, AES256_GCM2], encrypt2("aes256-gcm@openssh.com")
    end

    def test_none_for_encryption
      assert_equal TEXT, encrypt("none").strip
    end

    def test_none_for_decryption
      assert_equal TEXT, decrypt("none", TEXT)
    end

    private

    TEXT = "But soft! What light through yonder window breaks? It is the east, and Juliet is the sun!"
    TEXT2 = "2But soft! What light through yonder window breaks? It is the east, and Juliet is the sun!"

    OPTIONS = { iv: "ABC",
                key: "abc",
                digester: OpenSSL::Digest::MD5,
                shared: "1234567890123456780",
                hash: '!@#$%#$^%$&^&%#$@$' }

    def factory
      Net::SSH::Transport::CipherFactory
    end

    def encrypt(type)
      cipher = factory.get(type, OPTIONS.merge(encrypt: true))
      padding = TEXT.length % cipher.block_size
      result = cipher.update(TEXT.dup)
      result << cipher.update(" " * (cipher.block_size - padding)) if padding > 0
      result << cipher.final
    end

    def encrypt2(type)
      cipher = factory.get(type, OPTIONS.merge(encrypt: true))
      padding = TEXT.length % cipher.block_size
      result = cipher.update(TEXT.dup)
      result << cipher.update(" " * (cipher.block_size - padding)) if padding > 0
      result << cipher.final

      cipher.reset

      cipher.iv = "012345678912"

      padding = TEXT2.length % cipher.block_size
      result2 = cipher.update(TEXT2.dup)
      result2 << cipher.update(" " * (cipher.block_size - padding)) if padding > 0
      result2 << cipher.final
      [result, result2]
    end

    def decrypt(type, data)
      cipher = factory.get(type, OPTIONS.merge(decrypt: true))
      result = cipher.update(data.dup)
      result << cipher.final
      result.strip
    end

    def decrypt2(type, datas)
      cipher = factory.get(type, OPTIONS.merge(decrypt: true))
      result = cipher.update(datas[0].dup)
      result << cipher.final
      first = result.strip

      cipher.reset

      result = cipher.update(datas[1].dup)
      result << cipher.final
      second = result.strip
      [first, second]
    end
  end
end
