require 'dl/import'

if RUBY_VERSION < "1.9"
  require 'dl/struct'
else
  require 'dl/types'
  require 'dl'
end

require 'net/ssh/errors'

module Net; module SSH; module Authentication

  # This module encapsulates the implementation of a socket factory that
  # uses the PuTTY "pageant" utility to obtain information about SSH
  # identities.
  #
  # This code is a slightly modified version of the original implementation
  # by Guillaume Marçais (guillaume.marcais@free.fr). It is used and
  # relicensed by permission.
  module Pageant

    # From Putty pageant.c
    AGENT_MAX_MSGLEN = 8192
    AGENT_COPYDATA_ID = 0x804e50ba

    # The definition of the Windows methods and data structures used in
    # communicating with the pageant process.
    module Win
      if RUBY_VERSION < "1.9"
        extend DL::Importable

        dlload 'user32'
        dlload 'kernel32'
      else
        extend DL::Importer
        dlload 'user32','kernel32'
        include DL::Win32Types
      end

      typealias("LPCTSTR", "char *")         # From winnt.h
      typealias("LPVOID", "void *")          # From winnt.h
      typealias("LPCVOID", "const void *")   # From windef.h
      typealias("LRESULT", "long")           # From windef.h
      typealias("WPARAM", "unsigned int *")  # From windef.h
      typealias("LPARAM", "long *")          # From windef.h
      typealias("PDWORD_PTR", "long *")      # From basetsd.h

      # From winbase.h, winnt.h
      INVALID_HANDLE_VALUE = -1
      NULL = nil
      PAGE_READWRITE = 0x0004
      FILE_MAP_WRITE = 2
      WM_COPYDATA = 74

      SMTO_NORMAL = 0   # From winuser.h

      # args: lpClassName, lpWindowName
      extern 'HWND FindWindow(LPCTSTR, LPCTSTR)'

      # args: none
      extern 'DWORD GetCurrentThreadId()'

      # args: hFile, (ignored), flProtect, dwMaximumSizeHigh,
      #           dwMaximumSizeLow, lpName
      extern 'HANDLE CreateFileMapping(HANDLE, void *, DWORD, DWORD, ' +
        'DWORD, LPCTSTR)'

      # args: hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, 
      #           dwfileOffsetLow, dwNumberOfBytesToMap
      extern 'LPVOID MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, DWORD)'

      # args: lpBaseAddress
      extern 'BOOL UnmapViewOfFile(LPCVOID)'

      # args: hObject
      extern 'BOOL CloseHandle(HANDLE)'

      # args: hWnd, Msg, wParam, lParam, fuFlags, uTimeout, lpdwResult
      extern 'LRESULT SendMessageTimeout(HWND, UINT, WPARAM, LPARAM, ' +
        'UINT, UINT, PDWORD_PTR)'
      if RUBY_VERSION < "1.9"
        alias_method :FindWindow,:findWindow
        module_function :FindWindow
      end
    end

    # This is the pseudo-socket implementation that mimics the interface of
    # a socket, translating each request into a Windows messaging call to
    # the pageant daemon. This allows pageant support to be implemented
    # simply by replacing the socket factory used by the Agent class.
    class Socket

      private_class_method :new

      # The factory method for creating a new Socket instance. The location
      # parameter is ignored, and is only needed for compatibility with
      # the general Socket interface.
      def self.open(location=nil)
        new
      end

      # Create a new instance that communicates with the running pageant 
      # instance. If no such instance is running, this will cause an error.
      def initialize
        @win = Win.FindWindow("Pageant", "Pageant")

        if @win == 0
          raise Net::SSH::Exception,
            "pageant process not running"
        end

        @input_buffer = Net::SSH::Buffer.new
        @output_buffer = Net::SSH::Buffer.new
      end

      # Forwards the data to #send_query, ignoring any arguments after
      # the first.
      def send(data, *args)
        @input_buffer.append(data)
        
        ret = data.length
        
        while true
          return ret if @input_buffer.length < 4
          msg_length = @input_buffer.read_long + 4
          @input_buffer.reset!
      
          return ret if @input_buffer.length < msg_length
          msg = @input_buffer.read!(msg_length)
          @output_buffer.append(send_query(msg))
        end
      end
      
      # Reads +n+ bytes from the cached result of the last query. If +n+
      # is +nil+, returns all remaining data from the last query.
      def read(n = nil)
        @output_buffer.read(n)
      end

      def close
      end
      
      def send_query(query)
        if RUBY_VERSION < "1.9"
          send_query_18(query)
        else
          send_query_19(query)
        end
      end
      
      # Packages the given query string and sends it to the pageant
      # process via the Windows messaging subsystem. The result is
      # cached, to be returned piece-wise when #read is called.
      def send_query_18(query)
        res = nil
        filemap = 0
        ptr = nil
        id = DL::PtrData.malloc(DL.sizeof("L"))

        mapname = "PageantRequest%08x\000" % Win.getCurrentThreadId()
        filemap = Win.createFileMapping(Win::INVALID_HANDLE_VALUE, 
                                        Win::NULL,
                                        Win::PAGE_READWRITE, 0, 
                                        AGENT_MAX_MSGLEN, mapname)
        if filemap == 0
          raise Net::SSH::Exception,
            "Creation of file mapping failed"
        end

        ptr = Win.mapViewOfFile(filemap, Win::FILE_MAP_WRITE, 0, 0, 
                                AGENT_MAX_MSGLEN)

        if ptr.nil? || ptr.null?
          raise Net::SSH::Exception, "Mapping of file failed"
        end

        ptr[0] = query

        cds = [AGENT_COPYDATA_ID, mapname.size + 1, mapname].
          pack("LLp").to_ptr
        succ = Win.sendMessageTimeout(@win, Win::WM_COPYDATA, Win::NULL,
                                      cds, Win::SMTO_NORMAL, 5000, id)

        if succ > 0
          retlen = 4 + ptr.to_s(4).unpack("N")[0]
          res = ptr.to_s(retlen)
        end        

        return res
      ensure
        Win.unmapViewOfFile(ptr) unless ptr.nil? || ptr.null?
        Win.closeHandle(filemap) if filemap != 0
      end

      # Packages the given query string and sends it to the pageant
      # process via the Windows messaging subsystem. The result is
      # cached, to be returned piece-wise when #read is called.
      def send_query_19(query)
        res = nil
        filemap = 0
        ptr = nil
        id = DL.malloc(DL::SIZEOF_LONG)

        mapname = "PageantRequest%08x\000" % Win.GetCurrentThreadId()

        filemap = Win.CreateFileMapping(Win::INVALID_HANDLE_VALUE, 
                                        Win::NULL,
                                        Win::PAGE_READWRITE, 0, 
                                        AGENT_MAX_MSGLEN, mapname)

        if filemap == 0 || filemap == Win::INVALID_HANDLE_VALUE
          raise Net::SSH::Exception,
            "Creation of file mapping failed"
        end

        ptr = Win.MapViewOfFile(filemap, Win::FILE_MAP_WRITE, 0, 0, 
                                0)

        if ptr.nil? || ptr.null?
          raise Net::SSH::Exception, "Mapping of file failed"
        end

        DL::CPtr.new(ptr)[0,query.size]=query

        cds = DL::CPtr.to_ptr [AGENT_COPYDATA_ID, mapname.size + 1, mapname].
          pack("LLp")
        succ = Win.SendMessageTimeout(@win, Win::WM_COPYDATA, Win::NULL,
                                      cds, Win::SMTO_NORMAL, 5000, id)

        if succ > 0
          retlen = 4 + ptr.to_s(4).unpack("N")[0]
          res = ptr.to_s(retlen)
        end        

        return res
      ensure
        Win.UnmapViewOfFile(ptr) unless ptr.nil? || ptr.null?
        Win.CloseHandle(filemap) if filemap != 0
      end
    end
  end

end; end; end
