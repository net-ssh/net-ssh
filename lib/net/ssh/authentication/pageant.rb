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
        dlload 'advapi32'

        SIZEOF_DWORD = DL.sizeof('L')
      else
        extend DL::Importer
        dlload 'user32','kernel32', 'advapi32'
        include DL::Win32Types

        SIZEOF_DWORD = DL::SIZEOF_LONG
      end

      typealias("LPCTSTR", "char *")         # From winnt.h
      typealias("LPVOID", "void *")          # From winnt.h
      typealias("LPCVOID", "const void *")   # From windef.h
      typealias("LRESULT", "long")           # From windef.h
      typealias("WPARAM", "unsigned int *")  # From windef.h
      typealias("LPARAM", "long *")          # From windef.h
      typealias("PDWORD_PTR", "long *")      # From basetsd.h
      typealias("USHORT", "unsigned short")  # From windef.h

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
      
      # args: none
      extern 'DWORD GetLastError()'

      # args: none
      extern 'HANDLE GetCurrentProcess()'

      # args: hProcessHandle, dwDesiredAccess, (out) phNewTokenHandle
      extern 'BOOL OpenProcessToken(HANDLE, DWORD, PHANDLE)'

      # args: hTokenHandle, uTokenInformationClass,
      #           (out) lpTokenInformation, dwTokenInformationLength
      #           (out) pdwInfoReturnLength
      extern 'BOOL GetTokenInformation(HANDLE, UINT, LPVOID, DWORD, ' +
        'PDWORD)'

      # args: (out) lpSecurityDescriptor, dwRevisionLevel
      extern 'BOOL InitializeSecurityDescriptor(LPVOID, DWORD)'

      # args: (out) lpSecurityDescriptor, lpOwnerSid, bOwnerDefaulted
      extern 'BOOL SetSecurityDescriptorOwner(LPVOID, LPVOID, BOOL)'

      # args: pSecurityDescriptor
      extern 'BOOL IsValidSecurityDescriptor(LPVOID)'

      # Constants needed for security attribute retrieval.
      # Specifies the access mask corresponding to the desired access 
      # rights. 
      TOKEN_QUERY = 0x8

      # The value of TOKEN_USER from the TOKEN_INFORMATION_CLASS enum.
      TOKEN_USER_INFORMATION_CLASS = 1

      # The initial revision level assigned to the security descriptor.
      REVISION = 1

      if RUBY_VERSION < "1.9"
        alias_method :FindWindow,:findWindow
        module_function :FindWindow

        TOKEN_USER = struct ['void * SID', 'DWORD ATTRIBUTES']
        SECURITY_ATTRIBUTES = struct ['DWORD nLength',
                                      'LPVOID lpSecurityDescriptor',
                                      'BOOL bInheritHandle']
        SECURITY_DESCRIPTOR = struct ['UCHAR Revision', 'UCHAR Sbz1',
                                      'USHORT Control', 'LPVOID Owner',
                                      'LPVOID Group', 'LPVOID Sacl',
                                      'LPVOID Dacl']
        def self.get_security_attributes_for_user
          user = get_current_user
          #psid = DL::CPtr.new(user.SID.to_i)
          psd_information = DL.malloc(Win::SECURITY_DESCRIPTOR.size)
          raise_error_if_zero(
            Win.initializeSecurityDescriptor(psd_information, Win::REVISION))
          
          #puts "SID: #{user.SID.ptr.to_i}"
          raise_error_if_zero(
            Win.setSecurityDescriptorOwner(psd_information, user.SID, 0))
          raise_error_if_zero(
            Win.isValidSecurityDescriptor(psd_information))
          nLength = Win::SECURITY_ATTRIBUTES.size
          lpSecurityDescriptor = psd_information
          bInheritHandle = 1
          sa = [nLength, lpSecurityDescriptor.to_i, bInheritHandle].pack("LLC")

          return sa
        end

        def self.get_current_user
          token_handle = open_process_token(Win.getCurrentProcess,
                                            Win::TOKEN_QUERY)
          token_user =  get_token_information(token_handle,
                                       Win::TOKEN_USER_INFORMATION_CLASS)
          return token_user
        end

        def self.open_process_token(process_handle, desired_access)
          ptoken_handle = DL.malloc(Win::SIZEOF_DWORD)

          raise_error_if_zero(
            Win.openProcessToken(process_handle, desired_access,
                             ptoken_handle))
          token_handle = ptoken_handle.ptr.to_i
          return token_handle
        end

        def self.get_token_information(token_handle,
                                       token_information_class)
          # Hold the size of the information to be returned
          preturn_length = DL.malloc(Win::SIZEOF_DWORD)
          
          # Going to throw an INSUFFICIENT_BUFFER_ERROR, but that is ok
          # here. This is retrieving the size of the information to be
          # returned.
          Win.getTokenInformation(token_handle,
                              token_information_class,
                              Win::NULL, 0, preturn_length)
          ptoken_information = DL.malloc(preturn_length.ptr.to_i)

          # This call is going to write the requested information to
          # the memory location referenced by token_information.
          raise_error_if_zero(
            Win.getTokenInformation(token_handle,
                                token_information_class,
                                ptoken_information,
                                ptoken_information.size,
                                preturn_length))
          token_information = ptoken_information.ptr.to_i
          #puts "token_information: #{token_information.inspect}"
          #puts "token_information int: #{token_information.to_i}"
          return TOKEN_USER.new(ptoken_information)
        end

        def self.raise_error_if_zero(result)
          if result == 0
            raise "Windows error: #{Win.GetLastError}"
          end
        end
      else
        # Structs for security attribute functions.
        TOKEN_USER = struct ['void * SID', 'DWORD ATTRIBUTES']
        SECURITY_ATTRIBUTES = struct ['DWORD nLength',
                                      'LPVOID lpSecurityDescriptor',
                                      'BOOL bInheritHandle']
        SECURITY_DESCRIPTOR = struct ['UCHAR Revision', 'UCHAR Sbz1',
                                      'USHORT Control', 'LPVOID Owner',
                                      'LPVOID Group', 'LPVOID Sacl',
                                      'LPVOID Dacl']

        # Retrieves the security attributes for the current user, which
        # can be used in constructing the shared file mapping.
        def self.get_security_attributes_for_user
          user = get_current_user
          #psid = DL::CPtr.new(user.SID.to_i)
          psd_information = DL::CPtr.malloc(Win::SECURITY_DESCRIPTOR.size, DL::RUBY_FREE)
          raise_error_if_zero(
            Win.InitializeSecurityDescriptor(psd_information, Win::REVISION))
          
          #puts "SID: #{user.SID.ptr.to_i}"
          raise_error_if_zero(
            Win.SetSecurityDescriptorOwner(psd_information, user.SID, 0))
          raise_error_if_zero(
            Win.IsValidSecurityDescriptor(psd_information))
          nLength = Win::SECURITY_ATTRIBUTES.size
          lpSecurityDescriptor = psd_information
          bInheritHandle = 1
          sa = [nLength, lpSecurityDescriptor, bInheritHandle].pack("LLC")

          return sa
        end

        def self.get_current_user
          token_handle = open_process_token(Win.GetCurrentProcess,
                                            Win::TOKEN_QUERY)
          token_user =  get_token_information(token_handle,
                                       Win::TOKEN_USER_INFORMATION_CLASS)
          return token_user
        end

        def self.open_process_token(process_handle, desired_access)
          ptoken_handle = DL::CPtr.malloc(DL::SIZEOF_VOIDP, DL::RUBY_FREE)

          raise_error_if_zero(
            Win.OpenProcessToken(process_handle, desired_access,
                             ptoken_handle))
          token_handle = ptoken_handle.ptr.to_i
          return token_handle
        end

        def self.get_token_information(token_handle,
                                       token_information_class)
          # Hold the size of the information to be returned
          preturn_length = DL::CPtr.malloc(Win::SIZEOF_DWORD, DL::RUBY_FREE)
          
          # Going to throw an INSUFFICIENT_BUFFER_ERROR, but that is ok
          # here. This is retrieving the size of the information to be
          # returned.
          Win.GetTokenInformation(token_handle,
                              token_information_class,
                              Win::NULL, 0, preturn_length)
          ptoken_information = DL::CPtr.malloc(preturn_length.ptr.to_i, DL::RUBY_FREE)

          # This call is going to write the requested information to
          # the memory location referenced by token_information.
          raise_error_if_zero(
            Win.GetTokenInformation(token_handle,
                                token_information_class,
                                ptoken_information,
                                ptoken_information.size,
                                preturn_length))
          token_information = ptoken_information.ptr.to_i
          #puts "token_information: #{token_information.inspect}"
          #puts "token_information int: #{token_information.to_i}"
          return TOKEN_USER.new(ptoken_information)
        end

        def self.raise_error_if_zero(result)
          if result == 0
            raise "Windows error: #{Win.GetLastError}"
          end
        end
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
        security_attributes = Win.get_security_attributes_for_user.to_ptr
        filemap = Win.createFileMapping(Win::INVALID_HANDLE_VALUE, 
                                        security_attributes,
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
        security_attributes = DL::CPtr.to_ptr Win.get_security_attributes_for_user
        filemap = Win.CreateFileMapping(Win::INVALID_HANDLE_VALUE, 
                                        security_attributes,
                                        Win::PAGE_READWRITE, 0, 
                                        AGENT_MAX_MSGLEN, mapname)

        if filemap == 0 || filemap == Win::INVALID_HANDLE_VALUE
          raise Net::SSH::Exception,
            "Creation of file mapping failed; Windows error: #{Win.GetLastError}"
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
        else
          raise Net::SSH::Exception, "Message failed with error: #{Win.GetLastError}"
        end

        return res
      ensure
        Win.UnmapViewOfFile(ptr) unless ptr.nil? || ptr.null?
        Win.CloseHandle(filemap) if filemap != 0
      end
    end
  end

end; end; end
