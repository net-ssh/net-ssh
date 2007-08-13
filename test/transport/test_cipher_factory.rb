$LOAD_PATH.unshift("#{File.dirname(__FILE__)}/..").uniq!
require 'common'
require 'net/ssh/transport/cipher_factory'

module Transport

  class TestCipherFactory < Test::Unit::TestCase
    def test_lengths_for_none
      assert_equal [0,0], factory.get_lengths("none")
      assert_equal [0,0], factory.get_lengths("bogus")
    end

    def test_lengths_for_blowfish_cbc
      assert_equal [16,8], factory.get_lengths("blowfish-cbc")
    end

    def test_lengths_for_idea_cbc
      assert_equal [16,8], factory.get_lengths("idea-cbc")
    end

    def test_lengths_for_rijndael_cbc
      assert_equal [32,16], factory.get_lengths("rijndael-cbc@lysator.liu.se")
    end

    def test_lengths_for_cast128_cbc
      assert_equal [16,8], factory.get_lengths("cast128-cbc")
    end

    def test_lengths_for_3des_cbc
      assert_equal [24,8], factory.get_lengths("3des-cbc")
    end

    def test_lengths_for_aes192_cbc
      assert_equal [24,16], factory.get_lengths("aes192-cbc")
    end

    def test_lengths_for_aes128_cbc
      assert_equal [16,16], factory.get_lengths("aes128-cbc")
    end

    def test_lengths_for_aes256_cbc
      assert_equal [32,16], factory.get_lengths("aes256-cbc")
    end

    BLOWFISH = "\205D\376ZWk\343\312\b\n\336z\234\275BP\032l\366{v)\227\000\255\en\025\360y\251\322\354<&\370\330\304w2\251Gs\307\265Rs.G2W\234t|\202Y{\246\317\377\303_\006\336\022T\to\312\251Q^\202\001\224R\305\343o\237C-\272\357\016)\026}Hz\205*\326\226\312\242"

    def test_blowfish_cbc_for_encryption
      assert_equal BLOWFISH, encrypt("blowfish-cbc")
    end

    def test_blowfish_cbc_for_decryption
      assert_equal TEXT, decrypt("blowfish-cbc", BLOWFISH)
    end

    IDEA = "\002:\b\001\232\215b\314\3250\366D\230c>}\316\310\212\314b\254\344r\004\354/\232\360\232\205.\277\324\321+\220\377\244@\341?\315g<\204\016P!\243\341A\006\343&b\035\371\233\246p\277\350\230\226\275\207-\"\374\231lxfR\303s\336i\215\221C\003*\233\325\226\376\243\341\213\353Q\235<\250"

    def test_idea_cbc_for_encryption
      assert_equal IDEA, encrypt("idea-cbc")
    end

    def test_idea_cbc_for_decryption
      assert_equal TEXT, decrypt("idea-cbc", IDEA)
    end

    RIJNDAEL = "\255Q\200\333D\352\211x\324-\314\303\354\247w\002\242\357\177\272\243:\351=\307j\364\202\250E\327k\222\335\316\246\023\024\177\202\302\374\252X\375\260'\261\027\325\206\004[\030g\341[\e_\373\357\017\302-.\023.8\322\317\e\354=\326/\016>\305\262G\323'\356\343h\373LxR\330}P\274\254a\271"

    def test_rijndael_cbc_for_encryption
      assert_equal RIJNDAEL, encrypt("rijndael-cbc@lysator.liu.se")
    end

    def test_rijndael_cbc_for_decryption
      assert_equal TEXT, decrypt("rijndael-cbc@lysator.liu.se", RIJNDAEL)
    end

    CAST128 = "\022Z\231R^+\bR\223`\277\317#\352\202PX\255\320\024\177\313Pv\036\031\331r7\206\330\016R\205\324X\304\351\350\344\261l\264\230\003\241\235\260p\002Z-\n\221;\337F\336\312\036\177\177\351\246\n\216\336\334$3\a\365\234\342\306I\214M^(#\a\213D\245\211rdt#\202\336\316\020f$"

    def test_cast128_cbc_for_encryption
      assert_equal CAST128, encrypt("cast128-cbc")
    end

    def test_cast128_cbc_for_decryption
      assert_equal TEXT, decrypt("cast128-cbc", CAST128)
    end

    TRIPLE_DES = "q\\K,\244\213\361\277\rg3\3512\016\267\277Y\317\3469\rn\207:\201M\276\324\f\236\377\305\211^D\271g)A\227\024\225\363\220#\f\231\237x\361)\214\3519,\372\312\250\305.\204\325ou\224\277\344\022h\e\374\253\370G\373e\223n\302]\224\233\377\377R\023\310\271\326\352\334\001\302>\360\032"

    def test_3des_cbc_for_encryption
      assert_equal TRIPLE_DES, encrypt("3des-cbc")
    end

    def test_3des_cbc_for_decryption
      assert_equal TEXT, decrypt("3des-cbc", TRIPLE_DES)
    end

    AES128 = "d\323\025\301\313:M\360\372\034\tW\355\315i0\363v \001\371z\371\020\367\312\342\216\343\245\212\302\240\307q\272,\274\bf\226\314\263\215\247v^w\325F\242lv\300\f`\206\370\244D\004\375\363\306\016c\244W\363\243g\365\006cqm\256!\224U]\265\303\215\356\v\254`W\305eW\317\032I\221"

    def test_aes128_cbc_for_encryption
      assert_equal AES128, encrypt("aes128-cbc")
    end

    def test_aes128_cbc_for_decryption
      assert_equal TEXT, decrypt("aes128-cbc", AES128)
    end

    AES192 = "\370\215\211\344\275\202.\025\202\311V\324m6c\226>fhD\370\362\253\200v\253\237\027,\361\376^\335 \030\324\307\243\026[5Yf\f\224<gj\217\375\312\310.j\217\357\227L\241\t\327y\254l1\272\362\366\366M\"Iw\v\250\v\217\355\361\020\341)zp\257\0371\275f\035\337Y?\352S/"

    def test_aes192_cbc_for_encryption
      assert_equal AES192, encrypt("aes192-cbc")
    end

    def test_aes192_cbc_for_decryption
      assert_equal TEXT, decrypt("aes192-cbc", AES192)
    end

    AES256 = "\255Q\200\333D\352\211x\324-\314\303\354\247w\002\242\357\177\272\243:\351=\307j\364\202\250E\327k\222\335\316\246\023\024\177\202\302\374\252X\375\260'\261\027\325\206\004[\030g\341[\e_\373\357\017\302-.\023.8\322\317\e\354=\326/\016>\305\262G\323'\356\343h\373LxR\330}P\274\254a\271"

    def test_aes256_cbc_for_encryption
      assert_equal AES256, encrypt("aes256-cbc")
    end

    def test_aes256_cbc_for_decryption
      assert_equal TEXT, decrypt("aes256-cbc", AES256)
    end

    def test_none_for_encryption
      assert_equal TEXT, encrypt("none").strip
    end

    def test_none_for_decryption
      assert_equal TEXT, decrypt("none", TEXT)
    end

    private

      TEXT = "But soft! What light through yonder window breaks? It is the east, and Juliet is the sun!"

      OPTIONS = { :iv => "abcdefghijklmnopqrstuvwxyz012345",
        :key => "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6",
        :digester => OpenSSL::Digest::MD5,
        :shared => "1234567890123456780",
        :hash => '!@#$%#$^%$&^&%#$@$'
      }

      def factory
        Net::SSH::Transport::CipherFactory
      end

      def encrypt(type)
        cipher = factory.get(type, OPTIONS.merge(:encrypt => true))
        padding = TEXT.length % cipher.block_size
        result = cipher.update(TEXT.dup)
        result << cipher.update(" " * (cipher.block_size - padding)) if padding > 0
        result << cipher.final
      end

      def decrypt(type, data)
        cipher = factory.get(type, OPTIONS.merge(:decrypt => true))
        result = cipher.update(data.dup)
        result << cipher.final
        result.strip
      end
  end

end
