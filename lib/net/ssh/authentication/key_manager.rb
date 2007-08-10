require 'net/ssh/errors'
require 'net/ssh/key_factory'
require 'net/ssh/loggable'
require 'net/ssh/authentication/agent'

module Net
  module SSH
    module Authentication

      # A trivial exception class used to report errors in the key manager.
      class KeyManagerError < Net::SSH::Exception; end

      # This class encapsulates all operations done by clients on a user's
      # private keys. In practice, the client should never need a reference
      # to a private key; instead, they grab a list of "identities" (public 
      # keys) that are available from the KeyManager, and then use
      # the KeyManager to do various private key operations using those
      # identities.
      #
      # The KeyManager also uses the Agent class to encapsulate the
      # ssh-agent. Thus, from a client's perspective it is completely
      # hidden whether an identity comes from the ssh-agent or from a file
      # on disk.
      class KeyManager
        include Loggable

        # The key manager instance to use for managing keys
        attr_writer :keys

        # The list of user key files that will be examined
        attr_reader :key_files

        # Create a new KeyManager. By default, the manager will
        # use the ssh-agent (if it is running).
        def initialize(logger)
          self.logger = logger
          @key_files = []
          @use_agent = true
          @known_identities = {}
          @agent = nil
        end

        # Clear all knowledge of any loaded user keys. This also clears the list
        # of default identity files that are to be loaded, thus making it
        # appropriate to use if a client wishes to NOT use the default identity
        # files.
        def clear!
          @key_files.clear
          @known_identities.clear
          self
        end

        # Add the given key_file to the list of key files that will be used.
        def add(key_file)
          @key_files.push(key_file).uniq!
          self
        end

        alias :<< :add

        # This is used as a hint to the KeyManager indicating that the agent
        # connection is no longer needed. Any other open resources may be closed
        # at this time.
        #
        # Calling this does NOT indicate that the KeyManager will no longer
        # be used. Identities may still be requested and operations done on
        # loaded identities, in which case, the agent will be automatically
        # reconnected. This method simply allows the client connection to be
        # closed when it will not be used in the immediate future.
        def finish
          close_agent
        end

        # Returns an array of identities (public keys) known to this manager.
        # The origin of the identities may be from files on disk or from an
        # ssh-agent. Note that identities from an ssh-agent are always listed
        # first in the array, with other identities coming after.
        def identities
          identities = []

          if agent
            agent.identities.each do |key|
              identities.push key
              @known_identities[key] = { :from => :agent }
            end
          end

          @key_files.each do |file|
            if File.readable?(file)
              begin
                key = KeyFactory.load_public_key(file + ".pub")
                identities.push key
                @known_identities[key] = { :from => :file, :file => file }
              rescue Exception => e
                error { "could not load public key file `#{file}.pub': #{e.class} (#{e.message})" }
              end
            end
          end

          identities
        end

        # Sign the given data, using the corresponding private key of the given
        # identity. If the identity was originally obtained from an ssh-agent,
        # then the ssh-agent will be used to sign the data, otherwise the
        # private key for the identity will be loaded from disk (if it hasn't
        # been loaded already) and will then be used to sign the data.
        #
        # Regardless of the identity's origin or who does the signing, this
        # will always return the signature in an SSH2-specified "signature
        # blob" format.
        def sign(identity, data)
          info = @known_identities[identity] or raise KeyManagerError, "the given identity is unknown to the key manager"

          if info[:key].nil? && info[:from] == :file
            begin
              info[:key] = KeyFactory.load_private_key(info[:file])
            rescue Exception => e 
              raise KeyManagerError, "the given identity is known, but the private key could not be loaded: #{e.class} (#{e.message})"
            end
          end

          if info[:key]
            return Net::SSH::Buffer.from(:string, identity.ssh_type,
              :string, info[:key].ssh_do_sign(data.to_s)).to_s
          end

          if info[:from] == :agent
            raise KeyManagerError, "the agent is no longer available" unless agent
            return agent.sign(identity, data.to_s)
          end

          raise KeyManagerError, "[BUG] can't determine identity origin (#{info.inspect})"
        end

        # Identifies whether the ssh-agent will be used or not.
        def use_agent?
          @use_agent
        end

        # Toggles whether the ssh-agent will be used or not. If true, an
        # attempt will be made to use the ssh-agent. If false, any existing
        # connection to an agent is closed and the agent will not be used.
        def use_agent=(use_agent)
          close_agent if !use_agent
          @use_agent = use_agent
        end

        def agent
          return unless use_agent?
          @agent ||= Agent.new(logger)
        rescue AgentNotAvailable
          @use_agent = false
          nil
        end

        # Closes any open connection to an ssh-agent.
        def close_agent
          @agent.close if @agent
          @agent = nil
        end
        private :close_agent
      end

    end
  end
end
