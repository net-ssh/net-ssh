# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'open3'
require_relative '../rakelib/changelog'

class TestChangelog < Minitest::Test
  HISTORY = <<~TXT
    === 8.0.0 rc4

      * Old entry [#1]
  TXT

  def setup
    @root = Dir.mktmpdir('net-ssh-changelog')
    FileUtils.mkdir_p(File.join(@root, 'changelog.d'))
    File.write(File.join(@root, 'changelog.d', 'README.md'), "docs\n")
    File.write(File.join(@root, 'CHANGES.txt'), HISTORY)
    @changelog = Changelog.new(@root)
  end

  def teardown
    FileUtils.rm_rf(@root)
  end

  def fragment(name, text)
    File.write(File.join(@root, 'changelog.d', name), text)
  end

  def changes
    File.read(File.join(@root, 'CHANGES.txt'))
  end

  def test_heading
    assert_equal '8.0.0 rc5', Changelog.heading(8, 0, 0, 'rc5')
    assert_equal '8.0.0', Changelog.heading(8, 0, 0, nil)
  end

  def test_release_groups_by_type_and_orders_by_number_descending
    fragment('1001.change.txt', "Older change [#1001]\n")
    fragment('1003.change.txt', "Newer change [#1003]\n")
    fragment('1002.security.txt', "Safer [GHSA-pfqh-p9vh-wx4p]\n")
    fragment('1002.breaking.txt', "Removed x [#1002]\n")
    fragment('1002.breaking.2.txt', "Removed y [#1002]\n")
    fragment('1004.breaking-security.txt', "Removed z [#1004]\n")
    fragment('1005.none.txt', "test only\n")

    @changelog.release('8.0.0 rc5')

    assert_equal <<~TXT, changes
      === 8.0.0 rc5

        * BREAKING: Security: Removed z [#1004]
        * BREAKING: Removed x [#1002]
        * BREAKING: Removed y [#1002]
        * Security: Safer [GHSA-pfqh-p9vh-wx4p]
        * Newer change [#1003]
        * Older change [#1001]

      === 8.0.0 rc4

        * Old entry [#1]
    TXT
    assert_equal ['README.md'], Dir.children(File.join(@root, 'changelog.d'))
  end

  def test_number_is_appended_when_body_has_no_refs
    fragment('1010.change.txt', "Wrapped\nover two lines\n")
    assert_includes @changelog.section('x'), "  * Wrapped over two lines [#1010]\n"
  end

  def test_number_is_appended_unless_text_ends_with_a_reference_list
    {
      'Fix `opts[:x]`' => 'Fix `opts[:x]` [#7]',
      'Honour opts[:x]' => 'Honour opts[:x] [#7]',
      'See [the docs]' => 'See [the docs] [#7]',
      'Fixed [#985, #1056]' => 'Fixed [#985, #1056]',
      'Fixed [#985,#1056]' => 'Fixed [#985,#1056]',
      'Safer [GHSA-pfqh-p9vh-wx4p]' => 'Safer [GHSA-pfqh-p9vh-wx4p]',
      'Safer [CVE-2024-12345, #7]' => 'Safer [CVE-2024-12345, #7]'
    }.each do |text, expected|
      fragment('7.change.txt', text)
      assert_equal "=== x\n\n  * #{expected}\n", @changelog.section('x')
    end
  end

  def test_reads_utf8_with_bom_and_crlf_regardless_of_locale
    File.write(File.join(@root, 'CHANGES.txt'), "\xEF\xBB\xBF=== Unreleased\r\n\r\n  * Kézzel írt [#2]\r\n\r\n#{HISTORY}".b)
    fragment('1.change.txt', "\xEF\xBB\xBFÁrvíztűrő\r\ntükörfúrógép\r\n".b)

    with_default_external(Encoding::US_ASCII) { @changelog.release('8.0.0 rc5') }

    assert_equal "=== 8.0.0 rc5\n\n  * Árvíztűrő tükörfúrógép [#1]\n  * Kézzel írt [#2]\n\n#{HISTORY}", changes.force_encoding('UTF-8')
  end

  def test_rejects_invalid_utf8
    fragment('1.change.txt', "caf\xE9".b)
    error = assert_raises(Changelog::Error) { @changelog.check }
    assert_includes error.message, '1.change.txt: is not valid UTF-8'
  end

  def test_ignores_dotfiles
    %w[.DS_Store .gitkeep .1.change.txt.swp].each { |name| fragment(name, "\0junk") }
    fragment('1.change.txt', 'x')
    assert_equal(['1.change.txt'], @changelog.check.map { |f| File.basename(f.path) })
  end

  def test_folds_unreleased_entries_after_fragments_of_the_same_group
    unreleased = <<~TXT
      === Unreleased

        * Hand-written change [#900]
        * Security: hand-written security fix [#901]
          continued on a second line
        * BREAKING: Security: hand-written [#902]

    TXT
    File.write(File.join(@root, 'CHANGES.txt'), "#{unreleased}#{HISTORY}")
    fragment('1000.change.txt', 'Fragment change')
    fragment('1001.security.txt', 'Fragment security')

    @changelog.release('8.0.0')

    assert_equal <<~TXT, changes
      === 8.0.0

        * BREAKING: Security: hand-written [#902]
        * Security: Fragment security [#1001]
        * Security: hand-written security fix [#901]
          continued on a second line
        * Fragment change [#1000]
        * Hand-written change [#900]

      === 8.0.0 rc4

        * Old entry [#1]
    TXT
  end

  def test_unreleased_only
    File.write(File.join(@root, 'CHANGES.txt'), "=== Unreleased\n\n  * Only entry\n\n#{HISTORY}")
    @changelog.release('8.0.0 rc5')
    assert_equal "=== 8.0.0 rc5\n\n  * Only entry\n\n#{HISTORY}", changes
  end

  def test_pre_release_with_nothing_to_release_leaves_changes_untouched_and_removes_none_fragments
    fragment('1.none.txt', '')
    assert_nil @changelog.section('8.0.0 rc5')
    assert_nil @changelog.release('8.0.0 rc5')
    assert_equal HISTORY, changes
    assert_equal ['README.md'], Dir.children(File.join(@root, 'changelog.d'))
  end

  def test_final_release_with_nothing_to_release_writes_a_no_changes_section
    fragment('1.none.txt', '')
    expected = "=== 8.0.0\n\n  * No changes since 8.0.0 rc4.\n"
    assert_equal expected, @changelog.section('8.0.0')
    assert_equal expected, @changelog.release('8.0.0')
    assert_equal "#{expected}\n#{HISTORY}", changes
    assert_equal ['README.md'], Dir.children(File.join(@root, 'changelog.d'))
  end

  def test_final_release_folds_an_empty_unreleased_heading
    File.write(File.join(@root, 'CHANGES.txt'), "=== Unreleased\n\n#{HISTORY}")
    @changelog.release('8.0.1')
    assert_equal "=== 8.0.1\n\n  * No changes since 8.0.0 rc4.\n\n#{HISTORY}", changes
  end

  def test_refuses_existing_heading
    fragment('1.change.txt', 'x')
    error = assert_raises(Changelog::Error) { @changelog.release('8.0.0 rc4') }
    assert_match(/already has/, error.message)
  end

  def test_invalid_fragments_are_reported_and_nothing_is_written
    fragment('1.change.txt', 'Fine')
    fragment('2.feature.txt', 'x')
    fragment('3.change.txt', "  \n")
    fragment('4.change.txt', "One\n\nTwo")
    fragment('5.change.md', 'x')
    fragment('6.breaking.txt', 'BREAKING: twice')
    fragment('7.change.txt', '* bullet')
    fragment('8.change.txt', Changelog::PLACEHOLDER)
    fragment('9.change.txt', 'TODO list is now sorted')
    fragment('Upper.change.txt', 'x')
    fragment('a-slug.change.txt', 'x')

    error = assert_raises(Changelog::Error) { @changelog.release('8.0.0') }
    [
      "2.feature.txt: unknown type 'feature'",
      '3.change.txt: is empty',
      '4.change.txt: must be a single paragraph',
      '5.change.md: file name must be',
      '6.breaking.txt: should not start with BREAKING:/Security:',
      '7.change.txt: should not start with a bullet',
      '8.change.txt: still contains the placeholder text',
      'Upper.change.txt: file name must be',
      'a-slug.change.txt: file name must be'
    ].each { |message| assert_includes error.message, message }
    refute_includes error.message, '1.change.txt'
    refute_includes error.message, '9.change.txt'
    assert_equal HISTORY, changes
    assert File.exist?(File.join(@root, 'changelog.d', '1.change.txt'))
  end

  def test_section_does_not_modify_files
    fragment('1.change.txt', 'x')
    before = changes
    @changelog.section('8.0.0')
    assert_equal before, changes
    assert File.exist?(File.join(@root, 'changelog.d', '1.change.txt'))
  end

  def test_new_fragment
    first = @changelog.new_fragment('1058', 'change', 'Did a thing')
    second = @changelog.new_fragment('1058', 'change')
    assert_equal '1058.change.txt', File.basename(first)
    assert_equal '1058.change.2.txt', File.basename(second)
    assert_equal "Did a thing\n", File.read(first)
    assert_equal "#{Changelog::PLACEHOLDER}\n", File.read(second)
    assert_raises(Changelog::Error) { @changelog.new_fragment('1058', 'feature') }
    assert_raises(Changelog::Error) { @changelog.new_fragment('#1058', 'change') }
    assert_raises(Changelog::Error) { @changelog.new_fragment('my-change', 'change') }
  end

  def test_check_parses_the_unreleased_section
    File.write(File.join(@root, 'CHANGES.txt'), "=== Unreleased\n\nno bullet\n\n#{HISTORY}")
    error = assert_raises(Changelog::Error) { @changelog.check }
    assert_match(/Cannot parse the Unreleased section/, error.message)
  end

  def test_release_stages_fragment_deletions_in_git
    git('init', '-q')
    fragment('1.change.txt', 'x')
    git('add', '.')
    git('commit', '-q', '-m', 'init')

    @changelog.release('8.0.0')

    assert_equal ['D  changelog.d/1.change.txt', ' M CHANGES.txt'].sort, git('status', '--porcelain').lines.map(&:chomp).sort
  end

  def test_vbump_pre_writes_the_pre_release_heading_and_stages_everything
    setup_rake_project
    fragment('1.change.txt', 'x')
    git('add', '.')
    git('commit', '-q', '-m', 'init')

    rake('vbump:pre')

    assert_match(/PRE += "rc5"/, File.read(File.join(@root, 'lib/net/ssh/version.rb')))
    assert_equal "=== 8.0.0 rc5\n\n  * x [#1]\n\n#{HISTORY}", changes
    git('add', '.')
    assert_equal ['D  changelog.d/1.change.txt', 'M  CHANGES.txt', 'M  lib/net/ssh/version.rb', 'A  lib/net/ssh/version.rb.old'].sort,
                 git('status', '--porcelain').lines.map(&:chomp).sort
  end

  def test_vbump_final_writes_the_final_heading
    setup_rake_project
    rake('vbump:final')
    assert_match(/PRE += nil/, File.read(File.join(@root, 'lib/net/ssh/version.rb')))
    assert_equal "=== 8.0.0\n\n  * No changes since 8.0.0 rc4.\n\n#{HISTORY}", changes
  end

  def test_vbump_with_invalid_fragment_leaves_version_untouched
    setup_rake_project
    fragment('1.feature.txt', 'x')
    version = File.read(File.join(@root, 'lib/net/ssh/version.rb'))

    out = rake('vbump:pre', success: false)

    assert_includes out, "1.feature.txt: unknown type 'feature'"
    assert_equal version, File.read(File.join(@root, 'lib/net/ssh/version.rb'))
    assert_equal %w[version.rb], Dir.children(File.join(@root, 'lib/net/ssh'))
    assert_equal HISTORY, changes
  end

  def with_default_external(encoding)
    verbose = $VERBOSE
    $VERBOSE = nil
    previous = Encoding.default_external
    Encoding.default_external = encoding
    yield
  ensure
    Encoding.default_external = previous
    $VERBOSE = verbose
  end

  # A copy of the Rakefile with what it loads, at a known version (8.0.0 rc4).
  def setup_rake_project
    source = File.expand_path('..', __dir__)
    %w[Rakefile net-ssh.gemspec rakelib/changelog.rb lib/net/ssh/version.rb].each do |path|
      FileUtils.mkdir_p(File.dirname(File.join(@root, path)))
      FileUtils.cp(File.join(source, path), File.join(@root, path))
    end
    version_path = File.join(@root, 'lib/net/ssh/version.rb')
    version = File.read(version_path).sub(/^(\s+TINY\s+=\s+).*$/, '\10').sub(/^(\s+PRE\s+=\s+).*$/, '\1"rc4"')
    File.write(version_path, version)
    git('init', '-q')
  end

  def rake(task, success: true)
    out, status = Open3.capture2e(Gem.ruby, '-S', 'rake', task, chdir: @root)
    assert_equal success, status.success?, out
    out
  end

  def git(*args)
    out, status = Open3.capture2e('git', '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false',
                                  '-C', @root, *args)
    assert status.success?, out
    out
  end
end
