require 'erb'
require 'coderay'
require 'redcloth'
require 'fileutils'
require "#{File.dirname(__FILE__)}/../lib/net/ssh/version"

def syntax_highlight(content, options={})
  content.gsub(/<h:code(?:\s+lang="(.*?)")?>(.*?)<\/h:code>/m) do |match|
    lang = $1 || "text"
    code = CodeRay.scan($2.strip, lang)
    result = code.div(:line_numbers => :table, :css => :class)
    result = "<notextile>#{result}</notextile>" if options[:textile]
    result
  end
end

def render(template, variables={})
  content = File.read("#{File.dirname(__FILE__)}/templates/#{template}.erb")
  erb = ERB.new(content)
  __value = nil
  __binding = binding
  variables.each do |name, __value|
    eval("#{name}=__value", __binding)
  end
  body = syntax_highlight(erb.result(__binding))
  @layout.result(__binding)
end

FAQ = [
  { :f => "login_password", :t => "log in using a password" },
  { :f => "login_pubkey",   :t => "log in using a public key" },
  { :f => "login_agent",    :t => "log in using an SSH agent" },
  { :f => "login_port",     :t => "log in using a non-standard port number" },
  { :f => "exec_simple",    :t => "simply execute a program" },
  { :f => "channels",       :t => "manipulate SSH channels directly (to execute a program)" },
  { :f => "capture_output", :t => "capture stdout or stderr from a program" },
  { :f => "stdin",          :t => "send data to a program via stdin" },
  { :f => "forward_local",  :t => "forward a port from my local host to another server via the remote host" },
  { :f => "forward_remote", :t => "forward a port from the remote host to the local host" },
  { :f => "forward_agent",  :t => "enable SSH agent forwarding" },
  { :f => "key_verify",     :t => "disable (or modify) the default host-key verification" },
  { :f => "proxy_http",     :t => "use an HTTP proxy" },
  { :f => "proxy_socks4",   :t => "use a SOCKS4 proxy" },
  { :f => "proxy_socks5",   :t => "use a SOCKS5 proxy" },
  { :f => "compression",    :t => "enable compression" },
  { :f => "exit_status",    :t => "check the exit status of a program" },
  { :f => "event_loop",     :t => "manage a custom SSH event loop" },
  { :f => "request_pty",    :t => "request that a pseudo-tty (pty) be allocated" },
  { :f => "login_shell",    :t => "request that a login shell be started" }
]

@layout = ERB.new(File.read("#{File.dirname(__FILE__)}/templates/layout.erb"))

base = "#{File.dirname(__FILE__)}/out"
FileUtils.mkdir_p(base)
FileUtils.cp("#{File.dirname(__FILE__)}/styles.css", base)

# write index.html
File.open("#{base}/index.html", "w") do |f|
  f.write(render(:index, :title => "Net::SSH", :root => "."))
end

# write FAQ pages
FileUtils.mkdir_p("#{base}/faq")
FAQ.each do |faq|
  file = "#{File.dirname(__FILE__)}/faq/#{faq[:f]}.txt"
  if !File.exists?(file)
    warn "no definition for `#{faq[:t]}' (#{faq[:f]})"
    next
  end

  content = syntax_highlight(File.read(file), :textile => true)
  content = RedCloth.new(content).to_html

  File.open("#{base}/faq/#{faq[:f]}.html", "w") do |f|
    f.write(render(:faq, :answer => content, :faq => faq, :title => "Net::SSH: #{faq[:t]}", :root => ".."))
  end
end

# write download/install page
File.open("#{base}/install.html", "w") do |f|
  f.write(render(:install, :title => "Net::SSH", :root => ".", :version => Net::SSH::Version.current))
end

# write developers page
File.open("#{base}/developers.html", "w") do |f|
  f.write(render(:developers, :title => "Net::SSH", :root => ".", :version => Net::SSH::Version.current))
end

# write overview page
File.open("#{base}/overview.html", "w") do |f|
  f.write(render(:overview, :title => "Net::SSH", :root => "."))
end

# write tutorial page
File.open("#{base}/tutorial.html", "w") do |f|
  f.write(render(:tutorial, :title => "Net::SSH", :root => "."))
end
