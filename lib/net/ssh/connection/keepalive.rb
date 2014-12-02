module Net; module SSH; module Connection

module Keepalive
  # Default IO.select timeout threshold
  DEFAULT_IO_SELECT_TIMEOUT = 300

  def initialize_keepalive
    @last_keepalive_sent_at = nil
    @unresponded_keepalive_count = 0
  end

  def keepalive_enabled?
    options[:keepalive]
  end

  def keepalive_interval
    options[:keepalive_interval] || DEFAULT_IO_SELECT_TIMEOUT
  end

  def should_send_keepalive?
    return false unless keepalive_enabled?
    return true unless @last_keepalive_sent_at
    Time.now - @last_keepalive_sent_at >= keepalive_interval
  end

  def keepalive_maxcount
    (options[:keepalive_maxcount] || 3).to_i
  end

  def send_keepalive_as_needed(readers, writers)
    return unless readers.nil? && writers.nil?
    return unless should_send_keepalive?
    info { "sending keepalive #{@unresponded_keepalive_count}" }

    @unresponded_keepalive_count += 1
    send_global_request("keepalive@openssh.com") { |success, response|
      puts "before zero => #{@unresponded_keepalive_count}"
      @unresponded_keepalive_count = 0
    }
    @last_keepalive_sent_at = Time.now
    if keepalive_maxcount > 0 && @unresponded_keepalive_count > keepalive_maxcount
      error { "Timeout, server #{host} not responding. Missed #{@unresponded_keepalive_count-1} timeouts." }
      raise Net::SSH::Timeout, "Timeout, server #{host} not responding."
    end
  end
end

end; end; end