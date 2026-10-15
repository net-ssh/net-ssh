# frozen_string_literal: true

require 'fileutils'
require 'open3'

# Builds CHANGES.txt sections from the fragment files in changelog.d/ (see CONTRIBUTING.md).
class Changelog
  class Error < StandardError; end

  # Output order of the groups in a release section; `none` fragments are never emitted.
  TYPES = {
    'breaking-security' => 'BREAKING: Security: ',
    'breaking' => 'BREAKING: ',
    'security' => 'Security: ',
    'change' => '',
    'none' => nil
  }.freeze

  FILENAME = /\A(?<id>[1-9]\d*|[a-z][a-z0-9-]*)\.(?<type>[a-z-]+)(?:\.(?<seq>[1-9]\d*))?\.txt\z/.freeze
  IGNORED_FILES = %w[README.md .gitkeep].freeze
  UNRELEASED = '=== Unreleased'
  PLACEHOLDER = 'TODO'

  Fragment = Struct.new(:path, :id, :type, :seq, :text) do
    def number
      Integer(id, exception: false)
    end

    def entry
      "#{TYPES.fetch(type)}#{text}"
    end

    def sort_key
      number ? [0, -number, seq] : [1, id, seq]
    end
  end

  attr_reader :dir, :changes_path

  def initialize(root)
    @root = root
    @dir = File.join(root, 'changelog.d')
    @changes_path = File.join(root, 'CHANGES.txt')
  end

  # Raises Error listing every invalid fragment; returns all fragments, including `none` ones.
  def fragments
    errors = []
    fragments = []
    entries_in_dir.each do |name|
      result = parse_fragment(name)
      result.is_a?(Fragment) ? fragments << result : errors << "changelog.d/#{name}: #{result}"
    end
    raise Error, "Invalid changelog fragments:\n  #{errors.join("\n  ")}" unless errors.empty?

    fragments.sort_by(&:sort_key)
  end

  alias check fragments

  # The text of the section for +heading+, or nil when there is nothing to release.
  def section(heading)
    entries = grouped_entries(fragments, split_changes(read_changes)[:unreleased])
    return nil if entries.empty?

    "=== #{heading}\n\n#{entries.join}"
  end

  # Writes the section for +heading+ to the top of CHANGES.txt, folding in any `=== Unreleased`
  # entries, and removes the consumed fragments; returns the section, or nil when there is nothing to release.
  def release(heading)
    all = fragments
    content = read_changes
    raise Error, "CHANGES.txt already has a '=== #{heading}' section" if content.lines.any? { |l| l.chomp == "=== #{heading}" }

    parts = split_changes(content)
    entries = grouped_entries(all, parts[:unreleased])
    return nil if entries.empty?

    rest = parts[:rest].empty? ? '' : "\n#{parts[:rest]}"
    File.write(changes_path, "#{parts[:preamble]}=== #{heading}\n\n#{entries.join}#{rest}")
    remove(all.map(&:path))
    "=== #{heading}\n\n#{entries.join}"
  end

  # Creates a fragment for PR/issue +id+ and returns its path; picks the next free `.N` suffix if needed.
  def new_fragment(id, type, text = nil)
    path = (1..).lazy.map { |seq| File.join(dir, fragment_name(id, type, seq)) }.find { |p| !File.exist?(p) }
    error = validate_name(File.basename(path))
    raise Error, error if error

    FileUtils.mkdir_p(dir)
    text = PLACEHOLDER if (text.nil? || text.strip.empty?) && type != 'none'
    File.write(path, "#{text}\n")
    path
  end

  def self.heading(major, minor, tiny, pre)
    ["#{major}.#{minor}.#{tiny}", pre].compact.join(' ')
  end

  private

  def entries_in_dir
    return [] unless Dir.exist?(dir)

    Dir.children(dir).sort - IGNORED_FILES
  end

  def fragment_name(id, type, seq)
    seq == 1 ? "#{id}.#{type}.txt" : "#{id}.#{type}.#{seq}.txt"
  end

  def validate_name(name)
    match = FILENAME.match(name)
    return "file name must be <number or slug>.<type>[.<n>].txt, types: #{TYPES.keys.join(', ')}" unless match
    return "unknown type '#{match[:type]}', expected one of: #{TYPES.keys.join(', ')}" unless TYPES.key?(match[:type])

    nil
  end

  # Returns a Fragment, or an error message.
  def parse_fragment(name)
    path = File.join(dir, name)
    return 'is not a file' unless File.file?(path)

    error = validate_name(name)
    return error if error

    match = FILENAME.match(name)
    fragment = Fragment.new(path, match[:id], match[:type], (match[:seq] || 1).to_i, nil)
    return fragment if fragment.type == 'none'

    text = parse_text(File.read(path))
    return text[:error] if text[:error]

    fragment.text = text[:text]
    fragment.text = "#{fragment.text} [##{fragment.number}]" if fragment.number && !fragment.text.end_with?(']')
    fragment
  end

  def parse_text(raw)
    lines = raw.strip.lines.map(&:strip)
    return { error: 'is empty' } if lines.empty?
    return { error: 'must be a single paragraph (no blank lines)' } if lines.include?('')

    text = lines.join(' ')
    return { error: 'still contains the TODO placeholder' } if text.start_with?(PLACEHOLDER)
    return { error: "should not start with a bullet, it's added when assembling" } if text.match?(/\A[*-] /)
    return { error: 'should not start with BREAKING:/Security:, the type adds the prefix' } if text.match?(/\A(BREAKING|Security):/i)

    { text: text }
  end

  def read_changes
    File.exist?(changes_path) ? File.read(changes_path) : ''
  end

  # Splits CHANGES.txt into the text before the first heading, the entries of a leading
  # `=== Unreleased` section (as lists of raw lines) and everything from the first released heading on.
  def split_changes(content)
    lines = content.lines
    first = lines.index { |l| l.start_with?('=== ') } || lines.size
    preamble = lines[0...first].join
    return { preamble: preamble, unreleased: [], rest: lines[first..].join } unless lines[first]&.chomp == UNRELEASED

    body_end = lines.index.with_index { |l, i| i > first && l.start_with?('=== ') } || lines.size
    { preamble: preamble, unreleased: unreleased_entries(lines[(first + 1)...body_end]), rest: lines[body_end..].join }
  end

  def unreleased_entries(lines)
    lines.each_with_object([]) do |line, entries|
      next if line.strip.empty?

      if line.match?(/\A\s*\* /)
        entries << [line]
      elsif entries.empty?
        raise Error, "Cannot parse the Unreleased section of CHANGES.txt near: #{line.strip}"
      else
        entries.last << line
      end
    end
  end

  # Fragments come before the hand-written Unreleased entries of the same group.
  def grouped_entries(fragments, unreleased)
    TYPES.keys.flat_map do |type|
      from_fragments = fragments.select { |f| f.type == type && type != 'none' }.map { |f| "  * #{f.entry}\n" }
      from_unreleased = unreleased.select { |lines| unreleased_type(lines.first) == type }.map do |lines|
        lines.join.end_with?("\n") ? lines.join : "#{lines.join}\n"
      end
      from_fragments + from_unreleased
    end
  end

  def unreleased_type(line)
    text = line.sub(/\A\s*\* /, '')
    TYPES.find { |_type, prefix| prefix && !prefix.empty? && text.start_with?(prefix) }&.first || 'change'
  end

  # `git rm` so the deletions are staged with the version bump; plain delete outside a git checkout.
  def remove(paths)
    return if paths.empty?

    relative = paths.map { |p| p.delete_prefix("#{@root}/") }
    _out, status = Open3.capture2e('git', '-C', @root, 'rm', '-q', '--', *relative)
    FileUtils.rm_f(paths) unless status.success?
  rescue SystemCallError
    FileUtils.rm_f(paths)
  end
end
