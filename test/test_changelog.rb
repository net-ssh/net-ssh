require 'minitest/autorun'
require 'tmpdir'
require 'open3'
require_relative '../rakelib/changelog'

class TestChangelog < Minitest::Test
  HISTORY = <<~TXT.freeze
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
    fragment('1002.security.txt', "Safer [GHSA-xxxx]\n")
    fragment('1002.breaking.txt', "Removed x [#1002]\n")
    fragment('1002.breaking.2.txt', "Removed y [#1002]\n")
    fragment('1004.breaking-security.txt', "Removed z [#1004]\n")
    fragment('a-slug.change.txt', "Slug entry\n")
    fragment('1005.none.txt', "test only\n")

    @changelog.release('8.0.0 rc5')

    assert_equal <<~TXT, changes
      === 8.0.0 rc5

        * BREAKING: Security: Removed z [#1004]
        * BREAKING: Removed x [#1002]
        * BREAKING: Removed y [#1002]
        * Security: Safer [GHSA-xxxx]
        * Newer change [#1003]
        * Older change [#1001]
        * Slug entry

      === 8.0.0 rc4

        * Old entry [#1]
    TXT
    assert_equal ['README.md'], Dir.children(File.join(@root, 'changelog.d'))
  end

  def test_number_is_appended_when_body_has_no_refs
    fragment('1010.change.txt', "Wrapped\nover two lines\n")
    assert_includes @changelog.section('x'), "  * Wrapped over two lines [#1010]\n"
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

  def test_nothing_to_release_leaves_changes_untouched
    fragment('1.none.txt', '')
    assert_nil @changelog.section('8.0.0')
    assert_nil @changelog.release('8.0.0')
    assert_equal HISTORY, changes
    assert File.exist?(File.join(@root, 'changelog.d', '1.none.txt'))
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
    fragment('8.change.txt', 'TODO')
    fragment('Upper.change.txt', 'x')

    error = assert_raises(Changelog::Error) { @changelog.release('8.0.0') }
    [
      "2.feature.txt: unknown type 'feature'",
      '3.change.txt: is empty',
      '4.change.txt: must be a single paragraph',
      '5.change.md: file name must be',
      '6.breaking.txt: should not start with BREAKING:/Security:',
      '7.change.txt: should not start with a bullet',
      '8.change.txt: still contains the TODO placeholder',
      'Upper.change.txt: file name must be'
    ].each { |message| assert_includes error.message, message }
    refute_includes error.message, '1.change.txt'
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
    assert_equal "TODO\n", File.read(second)
    assert_raises(Changelog::Error) { @changelog.new_fragment('1058', 'feature') }
    assert_raises(Changelog::Error) { @changelog.new_fragment('#1058', 'change') }
  end

  def test_release_stages_fragment_deletions_in_git
    git('init', '-q')
    fragment('1.change.txt', 'x')
    git('add', '.')
    git('commit', '-q', '-m', 'init')

    @changelog.release('8.0.0')

    assert_equal ['D  changelog.d/1.change.txt', ' M CHANGES.txt'].sort, git('status', '--porcelain').lines.map(&:chomp).sort
  end

  def git(*args)
    out, status = Open3.capture2e('git', '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false',
                                  '-C', @root, *args)
    assert status.success?, out
    out
  end
end
