module Net; module SSH; module Test

  class Channel
    attr_reader :script
    attr_writer :local_id, :remote_id

    def initialize(script)
      @script = script
      @local_id = @remote_id = nil
    end

    def local_id
      @local_id || Proc.new { @local_id or raise "local-id has not been set yet!" }
    end

    def remote_id
      @remote_id || Proc.new { @remote_id or raise "remote-id has not been set yet!" }
    end

    def inject_remote_delay!
      gets_data("")
    end

    def sends_exec(command, reply=true, success=true)
      script.sends_channel_request(self, "exec", reply, command, success)
    end

    def sends_subsystem(subsystem, reply=true, success=true)
      script.sends_channel_request(self, "subsystem", reply, subsystem, success)
    end

    def sends_data(data)
      script.sends_channel_data(self, data)
    end

    def sends_eof
      script.sends_channel_eof(self)
    end

    def sends_close
      script.sends_channel_close(self)
    end

    def gets_data(data)
      script.gets_channel_data(self, data)
    end

    def gets_exit_status(status=0)
      script.gets_channel_request(self, "exit-status", false, status)
    end

    def gets_eof
      script.gets_channel_eof(self)
    end

    def gets_close
      script.gets_channel_close(self)
    end
  end

end; end; end