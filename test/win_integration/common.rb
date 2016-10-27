$LOAD_PATH.unshift "#{File.dirname(__FILE__)}/../../lib"

require 'minitest/autorun'
require 'mocha/setup'
require 'pty'
require 'expect'
require_relative '../common'
