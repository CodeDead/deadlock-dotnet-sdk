using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using deadlock_dotnet_sdk.Exceptions;
using Microsoft.Win32.SafeHandles;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Storage.FileSystem;
using Windows.Win32.System.RestartManager;
using Windows.Win32.System.Threading;
using Windows.Win32.System.WindowsProgramming;
using static Windows.Win32.PInvoke;

// Re: StructLayout
// "C#, Visual Basic, and C++ compilers apply the Sequential layout value to structures by default."
// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.structlayoutattribute?view=net-6.0#remarks

// new Win32Exception() is defined as
// public Win32Exception() : this(Marshal.GetLastPInvokeError())
// {
// }

namespace deadlock_dotnet_sdk.Domain;

/// <summary>
/// Collection of native methods
/// </summary>
internal static class NativeMethods
{
    #region Variables

    private const int RmRebootReasonNone = 0;

    #endregion Variables

    #region Methods

    /// <summary>
    /// Find the processes that are locking a file
    /// </summary>
    /// <param name="path">Path to the file</param>
    /// <param name="rethrowExceptions">True if inner exceptions should be rethrown, otherwise false</param>
    /// <returns>A collection of processes that are locking a file</returns>
    internal static IEnumerable<Process> FindLockingProcesses(string path, bool rethrowExceptions)
    {
        unsafe
        {
            using (PWSTR key = new((char*)Marshal.StringToHGlobalUni(Guid.NewGuid().ToString())))
            {
                List<Process> processes = new();

                uint res = RmStartSession(out var handle, 0, key);
                if (res != 0)
                {
                    throw new StartSessionException();
                }

                try
                {
                    const int errorMoreData = 234;
                    uint pnProcInfo = 0;
                    uint lpdwRebootReasons = RmRebootReasonNone;

                    string[] resources = { path };
                    using (PWSTR pResources = (char*)Marshal.StringToHGlobalUni(path))
                    {
                        res = RmRegisterResources(handle, new Span<PWSTR>(new PWSTR[] { pResources }), rgApplications: new(), new());

                        if (res != 0)
                        {
                            pResources.Dispose();
                            throw new RegisterResourceException();
                        }

                        res = RmGetList(handle, out var pnProcInfoNeeded, ref pnProcInfo, null, out lpdwRebootReasons);

                        if (res == errorMoreData)
                        {
                            ReadOnlySpan<RM_PROCESS_INFO> processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                            pnProcInfo = pnProcInfoNeeded;

                            fixed (RM_PROCESS_INFO* pProcessInfo = processInfo)
                            {
                                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, pProcessInfo, out lpdwRebootReasons);
                            }
                            if (res == 0)
                            {
                                processes = new List<Process>((int)pnProcInfo);

                                for (int i = 0; i < pnProcInfo; i++)
                                {
                                    try
                                    {
                                        processes.Add(Process.GetProcessById((int)processInfo[i].Process.dwProcessId));
                                    }
                                    catch (ArgumentException)
                                    {
                                        pResources.Dispose();
                                        if (rethrowExceptions) throw;
                                    }
                                }
                            }
                            else
                            {
                                pResources.Dispose();
                                throw new RmListException();
                            }
                        }
                        else if (res != 0)
                        {
                            pResources.Dispose();
                            throw new UnauthorizedAccessException();
                        }
                    }
                }
                finally
                {
                    _ = RmEndSession(handle);
                    key.Dispose();
                }

                return processes;
            }
        }
    }

    /// <summary>
    /// Query the systems open handles, try to filter them to just files, and try to filter those files to just ones that contain the path query. 
    /// </summary>
    /// <param name="path"></param>
    /// <param name="rethrowExceptions"></param>
    /// <returns>A List of SafeFileHandle objects.</returns>
    /// <remarks>This might be arduously slow...</remarks>
    internal static List<SafeFileHandleEx> FindLockingHandles(string? path = null)
    {
        Process.EnterDebugMode(); // just in case

        List<SafeHandleEx> handles = GetSystemHandleInfoEx().ToArray().Cast<SafeHandleEx>().ToList();
        List<SafeFileHandleEx> fileHandles = new();
        foreach (var handle in handles)
        {
            var fileHandle = new SafeFileHandleEx(handle);
            // Do we need more path sanitation checks?
            if (!string.IsNullOrWhiteSpace(path) && (string.IsNullOrEmpty(fileHandle.FullPath) || fileHandle.FullPath.Contains(path)))
            {
                // we also add null-path handles bc we can assume we failed to query their paths. If someone wants to filter them out, they can.
                fileHandles.Add(fileHandle);
            }
            // else, the file handle's path is fulfilled, but does not match our query
        }

        fileHandles.Sort((a, b) => a.ProcessId.CompareTo(b.ProcessId));
        return fileHandles;
    }

    /// <summary>
    /// Get a Span of <see cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"/> via <see cref="NtQuerySystemInformation"/>
    /// </summary>
    /// <remarks>Heavily influenced by ProcessHacker/SystemInformer</remarks>
    private unsafe static Span<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> GetSystemHandleInfoEx()
    {
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        const uint PH_LARGE_BUFFER_SIZE = 256 * 1024 * 1024; // 256 Mebibytes
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xC000009A;
        uint systemInformationLength = (uint)sizeof(SYSTEM_HANDLE_INFORMATION_EX);
        SYSTEM_HANDLE_INFORMATION_EX* pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.AllocHGlobal(sizeof(SYSTEM_HANDLE_INFORMATION_EX));
        uint returnLength = 0;

        NTSTATUS status = NtQuerySystemInformation(
            SystemInformationClass: SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
            SystemInformation: pSysInfoBuffer,
            SystemInformationLength: systemInformationLength,
            ReturnLength: ref returnLength
            );

        for (uint attempts = 0; status == STATUS_INFO_LENGTH_MISMATCH && attempts < 10; attempts++)
        {
            systemInformationLength = returnLength;
            pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.ReAllocHGlobal((IntPtr)pSysInfoBuffer, (IntPtr)systemInformationLength);

            status = NtQuerySystemInformation(
                SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                pSysInfoBuffer,
                systemInformationLength,
                ref returnLength
                );
        }

        if (!status.IsSuccessful)
        {
            // Fall back to using the previous code that we've used since Windows XP (dmex)
            systemInformationLength = 0x10000;
            Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
            pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.ReAllocHGlobal((IntPtr)pSysInfoBuffer, (IntPtr)systemInformationLength);

            while ((status = NtQuerySystemInformation(
                SystemInformationClass: SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                SystemInformation: pSysInfoBuffer,
                SystemInformationLength: systemInformationLength,
                ReturnLength: ref returnLength
                )) == STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
                systemInformationLength *= 2;

                // Fail if we're resizing the buffer to something very large.
                if (systemInformationLength > PH_LARGE_BUFFER_SIZE)
                {
                    throw new Win32Exception(unchecked((int)STATUS_INSUFFICIENT_RESOURCES));
                }

                pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.AllocHGlobal((int)systemInformationLength);
            }
        }

        if (!status.IsSuccessful)
        {
            Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
            Marshal.FreeHGlobal((IntPtr)returnLength);
            throw new Win32Exception((int)status);
        }

        SYSTEM_HANDLE_INFORMATION_EX retVal = *pSysInfoBuffer;

        Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
        Marshal.FreeHGlobal((IntPtr)returnLength);

        return retVal.AsSpan();
    }

    /// <summary>
    /// A wrapper for QueryFullProcessImageName
    /// </summary>
    /// <param name="processId">
    /// The identifier of the local process to be opened.
    /// If the specified process is the System Idle Process(0x00000000),
    ///  the function fails and the last error code is ERROR_INVALID_PARAMETER.
    /// If the specified process is the System process or one of the Client Server Run-Time Subsystem(CSRSS) processes,
    ///  this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.
    /// </param>
    /// <param name="hProcess">A SafeProcessHandle opened with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION"/></param>
    /// <returns>The path to the executable image.</returns>
    /// <exception cref="Exception">Call to <see cref="OpenProcess(uint, bool, uint)"/> or <see cref="QueryFullProcessImageName(SafeProcessHandle, uint, out string, ref uint)"/> failed.</exception>
    private unsafe static string GetFullProcessImageName(SafeProcessHandle hProcess)
    {
        if (hProcess.IsInvalid)
        {
            throw new ArgumentException("The process handle is invalid", nameof(hProcess));
        }

        uint size = 260 + 1;
        uint bufferLength = size;
        IntPtr ptr = Marshal.AllocHGlobal((int)bufferLength);
        PWSTR buffer = new PWSTR((char*)ptr);

        if (!QueryFullProcessImageName(
            hProcess: hProcess,
            dwFlags: PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32,
            lpExeName: buffer,
            lpdwSize: ref size))
        {
            if (bufferLength < size)
            {
                ptr = Marshal.ReAllocHGlobal(ptr, (IntPtr)size);
                buffer = new((char*)ptr);
                _ = QueryFullProcessImageName(
                    hProcess,
                    PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32,
                    buffer,
                    ref size);
            }
            else
            {
                var err = Marshal.GetLastPInvokeError();
                hProcess.Close();
                throw new Win32Exception(err);
            }
        }

        // this is horribly inefficient. How many times are we creating new references and/or buffers?
        hProcess.Close();
        string retVal = buffer.ToString();
        Marshal.FreeHGlobal((IntPtr)buffer.Value);
        return retVal;
    }

    #endregion Methods

    #region Structs

    /// <summary>
    /// The <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm"><c>SYSTEM_HANDLE_INFORMATION_EX</c></see>
    /// struct is 0x24 or 0x38 bytes in 32-bit and 64-bit Windows, respectively. However, Handles is a variable-length array.
    /// </summary>
    public unsafe struct SYSTEM_HANDLE_INFORMATION_EX
    {
        /// <summary>
        /// As documented unofficially, NumberOfHandles is a 4-byte or 8-byte ULONG_PTR in 32-bit and 64-bit Windows, respectively.<br/>
        /// This is not to be confused with uint* or ulong*.
        /// </summary>
        public UIntPtr NumberOfHandles;
        public UIntPtr Reserved;
        public SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* Handles;

        public Span<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> AsSpan() => new(Handles, (int)NumberOfHandles);
        public static implicit operator Span<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(SYSTEM_HANDLE_INFORMATION_EX value) => value.AsSpan();
    }

    /// <summary><para>
    /// The <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry_ex.htm">
    /// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX</see>
    /// structure is a recurring element in the <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm">
    /// SYSTEM_HANDLE_INFORMATION_EX </see>
    /// struct that a successful call to <see href="https://docs.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation">
    /// ZwQuerySystemInformation</see>
    /// or <see href="https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation">
    /// NtQuerySystemInformation</see>
    /// produces in its output buffer when given the information class <see cref="SystemHandleInformation">
    /// SystemHandleInformation (0x10)</see>.</para>
    /// This inline doc was supplemented by ProcessHacker's usage of this struct.
    /// </summary>
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public unsafe void* Object;
        /// <summary>
        /// ULONG_PTR, cast to HANDLE, int, or uint
        /// </summary>
        public HANDLE UniqueProcessId;
        /// <summary>
        /// ULONG_PTR, cast to HANDLE
        /// </summary>
        public HANDLE HandleValue;
        /// <summary>
        /// This is a bitwise "Flags" data type.
        /// See the "Granted Access" column in the Handles section of a process properties window in ProcessHacker.
        /// </summary>
        public ACCESS_MASK GrantedAccess; // ULONG
        public ushort CreatorBackTraceIndex; // USHORT
        /// <summary>ProcessHacker defines a little over a dozen handle-able object types.</summary>
        public ushort ObjectTypeIndex; // USHORT
        /// <summary><see href="https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes#members"/></summary>
        public uint HandleAttributes; // ULONG
        public uint Reserved;

        /// <summary>
        /// Get the Type of the object as a string
        /// </summary>
        /// <exception cref="Exception">P/Invoke function NtQueryObject failed. See Exception data.</exception>
        /// <returns>The Type of the object as a string.</returns>
        public unsafe string GetObjectType()
        {
            /* Query the object type */
            string typeName;
            PUBLIC_OBJECT_TYPE_INFORMATION* objectTypeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION*)Marshal.AllocHGlobal(sizeof(PUBLIC_OBJECT_TYPE_INFORMATION));
            uint* returnLength = (uint*)Marshal.AllocHGlobal(sizeof(uint));
            NTSTATUS status;

            if ((status = NtQueryObject(HandleValue, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, objectTypeInfo, (uint)sizeof(PUBLIC_OBJECT_TYPE_INFORMATION), returnLength)).SeverityCode == NTSTATUS.Severity.Success)
            {
                typeName = objectTypeInfo->TypeName.ToStringLength();
                Marshal.FreeHGlobal((IntPtr)objectTypeInfo);
            }
            else
            {
                Marshal.FreeHGlobal((IntPtr)objectTypeInfo);
                throw new Win32Exception();
            }
            return typeName;
        }

        /// <summary>Invokes <see cref="GetObjectType()"/> and checks if the result is "File".</summary>
        /// <returns>True if the handle is for a file or directory.</returns>
        /// <remarks>Based on source of C/C++ projects <see href="https://www.x86matthew.com/view_post?id=hijack_file_handle">Hijack File Handle</see> and <see href="https://github.com/adamkramer/handle_monitor">Handle Monitor</see></remarks>
        /// <exception cref="Exception">Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. See InnerException for details.</exception>
        public bool IsFileHandle()
        {
            try
            {
                string type = GetObjectType();
                return !string.IsNullOrWhiteSpace(type) && string.CompareOrdinal(type, "File") == 0;
            }
            catch (Exception e)
            {
                throw new Exception("Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. See InnerException for details.", e);
            }
        }

        /// <summary>
        /// Try to cast this handle's <see cref="HandleValue"/> to a SafeFileHandle;
        /// </summary>
        /// <returns>A <see cref="SafeFileHandle"/> if this handle's object is a data/directory File.</returns>
        /// <exception cref="Exception">The handle's object is not a File -OR- perhaps NtQueryObject() failed. See <see cref="Exception.InnerException"/> for details.</exception>
        public SafeFileHandle ToSafeFileHandle()
        {
            return IsFileHandle()
                ? (new((nint)HandleValue, (int)UniqueProcessId == Environment.ProcessId))
                : throw new Exception("The handle's object is not a File -OR- NtQueryObject() failed. See InnerException for details.");
        }
    }

    #endregion Structs

    #region Classes

    /// <summary>
    /// A SafeHandleZeroOrMinusOneIsInvalid wrapping a SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX<br/>
    /// Before querying for system handles, call <see cref="Process.EnterDebugMode()"/> for easier access to restricted data.
    /// </summary>
    internal class SafeHandleEx : SafeHandleZeroOrMinusOneIsInvalid
    {
        private protected SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx;

        internal SafeHandleEx(bool ownsHandle = false) : base(ownsHandle)
        { }

        public SafeHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX newSysHandleEx, bool ownsHandle = false) : base(ownsHandle)
        {
            sysHandleEx = newSysHandleEx;
            Init();
        }

        internal void Init()
        {
            try
            {
                //Process.EnterDebugMode(); Best practice: only call this once.

                /** Open handle for process */
                // PROCESS_QUERY_LIMITED_INFORMATION is necessary for QueryFullProcessImageName
                // PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ for reading PEB from the process's memory space.
                // if we need to duplicate a handle later, we'll use PROCESS_DUP_HANDLE

                HANDLE rawHandle = OpenProcess(
                    dwDesiredAccess: PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ,
                    bInheritHandle: (BOOL)false,
                    dwProcessId: (uint)ProcessId
                );

                if (rawHandle.IsNull)
                    throw new Win32Exception("Failed to open process handle with access rights 'PROCESS_QUERY_LIMITED_INFORMATION' and 'PROCESS_VM_READ'. The following information will be unavailable: main module full name, process name, ");

                SafeProcessHandle hProcess = new(rawHandle, true);

                /** Get main module's full path */
                ProcessMainModulePath = GetFullProcessImageName(hProcess);

                /** Get Process's name */
                if (!string.IsNullOrWhiteSpace(ProcessMainModulePath))
                {
                    ProcessName = Path.GetFileNameWithoutExtension(ProcessMainModulePath);
                }

                /** Get process's possibly-overwritten command line from the PEB struct in its memory space */
                GetProcessCommandLine(hProcess);
            }
            catch (Exception e)
            {
                ExceptionLog.Add(e);
            }
        }

        internal SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX SysHandleEx => sysHandleEx;

        public unsafe void* Object => SysHandleEx.Object;
        /// <summary>
        /// cast to uint
        /// </summary>
        public HANDLE ProcessId => SysHandleEx.UniqueProcessId;
        public HANDLE HandleValue => SysHandleEx.HandleValue;
        public ushort CreatorBackTraceIndex => SysHandleEx.CreatorBackTraceIndex;
        /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.GrantedAccess"/>
        public ACCESS_MASK GrantedAccess => SysHandleEx.GrantedAccess;
        public ushort ObjectTypeIndex => SysHandleEx.ObjectTypeIndex;
        /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.HandleAttributes"/>
        public uint HandleAttributes => SysHandleEx.HandleAttributes;

        public string? ProcessCommandLine { get; private set; }
        public string? ProcessMainModulePath { get; private set; }
        public string? ProcessName { get; private set; }

        /// <summary>
        /// A list of exceptions thrown by constructors and other methods of this class.<br/>
        /// Intended to explain why the process command line, main module path, and name are unavailable.
        /// </summary>
        /// <remarks>Use List's methods (e.g. Add) to modify this list.</remarks>
        public static List<Exception> ExceptionLog { get; } = new();

        public void UnlockSystemHandle()
        {
            HANDLE rawHProcess;
            SafeProcessHandle? hProcess = null;
            try
            {
                if ((rawHProcess = OpenProcess(
                    PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE,
                    true,
                    (uint)ProcessId)
                    ).IsNull)
                {
                    throw new Win32Exception($"Failed to open process with id {(int)ProcessId} to duplicate and close object handle.");
                }

                hProcess = new(rawHProcess, true);
                if (DuplicateHandle(hProcess, this, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_CLOSE_SOURCE))
                {
                    dupHandle.Close();
                    hProcess.Close();

                    // finally, close this SafeHandleEx
                    Close();
                }
                else
                {
                    throw new Win32Exception("Function DuplicateHandle failed to duplicate the handle");
                }
            }
            catch (Exception e)
            {
                ExceptionLog.Add(e);
                if (hProcess is not null)
                    hProcess.Close();
            }
        }

        public string GetObjectType() => SysHandleEx.GetObjectType();

        /// <summary>
        /// Try to get a process's command line from its PEB
        /// </summary>
        /// <param name="hProcess"></param>
        /// <exception cref="NotImplementedException"></exception>
        /// <exception cref="Win32Exception"></exception>
        private unsafe void GetProcessCommandLine(SafeProcessHandle hProcess)
        {
            /* Get PROCESS_BASIC_INFORMATION */
            uint sysInfoLength = (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            PROCESS_BASIC_INFORMATION processBasicInfo;
            IntPtr sysInfo = Marshal.AllocHGlobal((int)sysInfoLength);
            NTSTATUS status = (NTSTATUS)0;
            uint retLength = 0;

            if ((status = NtQueryInformationProcess(
                hProcess,
                PROCESSINFOCLASS.ProcessBasicInformation,
                (void*)sysInfo,
                sysInfoLength,
                ref retLength))
                .IsSuccessful)
            {
                processBasicInfo = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(sysInfo);

                // if our process is WOW64, we need to account for different pointer sizes if
                // the target process is 64-bit
                IsWow64Process(hProcess, out BOOL wow64Process);
                if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess && wow64Process)
                {
                    throw new NotImplementedException("Reading a 64-bit process's PEB from a 32-bit process (under WOW64) is not yet implemented.");
                    // too much trouble. If someone else wants to do it, be my guest.
                    // https://stackoverflow.com/a/36798492/14894786
                    // Reason: if our process is 32-bit, we'd be stuck with 32-bit pointers. 
                    // If the PEB's address is in 64-bit address space, we can't access it 
                    // because the pointer value we received was truncated from 64 bits to 
                    // 32 bits.
                }

                IntPtr buf = Marshal.AllocHGlobal(sizeof(PEB));
                if (ReadProcessMemory(hProcess, processBasicInfo.PebBaseAddress, (void*)buf, (nuint)sizeof(PEB), null))
                {
                    PEB peb = Marshal.PtrToStructure<PEB>(buf);
                    ProcessCommandLine = (*peb.ProcessParameters).CommandLine.ToStringLength();
                }
                else
                {
                    // this calls Marshal.GetLastPInvokeError()
                    // https://sourcegraph.com/github.com/dotnet/runtime@main/-/blob/src/libraries/System.Private.CoreLib/src/System/ComponentModel/Win32Exception.cs?L46
                    throw new Win32Exception("Failed to read the process's PEB in memory. While trying to read the PEB, the operation crossed into an area of the process that is inaccessible.");
                }
            }
            else
            {
                throw new Exception("NtQueryInformationProcess failed to query the process's 'PROCESS_BASIC_INFORMATION'");
            }
        }

        protected override bool ReleaseHandle()
        {
            Close();
            return IsClosed;
        }
    }

    internal class SafeFileHandleEx : SafeHandleEx
    {
        // TODO: there's gotta be a better way to cast a base class to an implementing class
        internal SafeFileHandleEx(SafeHandleEx safeHandleEx)
        {
            sysHandleEx = safeHandleEx.SysHandleEx;
            Init();
            InitFile();
        }

        public SafeFileHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx, bool ownsHandle) : base(newSysHandleEx: sysHandleEx, ownsHandle: ownsHandle)
        {
            //base.sysHandleEx = sysHandleEx;
            //Init();
            InitFile();
        }

        private void InitFile()
        {
            bool? isFileHandle;
            try
            {
                isFileHandle = sysHandleEx.IsFileHandle();
            }
            catch (Exception)
            {
                isFileHandle = null;
                // IsFileHandle failed
            }
            if (isFileHandle == true)
            {
                FullPath = TryGetFinalPath();
                if (FullPath != null)
                {
                    Name = Path.GetFileName(FullPath);
                    IsDirectory = (File.GetAttributes(FullPath) & FileAttributes.Directory) == FileAttributes.Directory;
                }
            }
            else
            {
                throw new InvalidCastException("Cannot cast non-file handle to file handle!");
            }
        }

        public string? FullPath { get; private set; }
        public string? Name { get; private set; }
        public bool? IsDirectory { get; private set; }

        /// <summary>
        /// Try to get the absolute path of the file. Traverses filesystem links (e.g. symbolic, junction) to get the 'real' path.
        /// </summary>
        /// <returns>If successful, returns a path string formatted as 'X:\dir\file.ext' or 'X:\dir'</returns>
        /// <exception cref="FileNotFoundException(string, string)">The path '{fullName}' was not found when querying a file handle.</exception>
        /// <exception cref="OutOfMemoryException(string)">Failed to query path from file handle. Insufficient memory to complete the operation.</exception>
        /// <exception cref="ArgumentException">Failed to query path from file handle. Invalid flags were specified for dwFlags.</exception>
        private unsafe string TryGetFinalPath()
        {
            /// Return the normalized drive name. This is the default.
            uint bufLength = (uint)short.MaxValue;
            var buffer = Marshal.AllocHGlobal((int)bufLength);
            PWSTR fullName = new((char*)buffer);
            uint length = GetFinalPathNameByHandle(SysHandleEx.ToSafeFileHandle(), fullName, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);

            if (length != 0)
            {
                while (length > bufLength)
                {
                    // buffer was too small. Reallocate buffer with size matched 'length' and try again
                    buffer = Marshal.ReAllocHGlobal(buffer, (IntPtr)length);
                    fullName = new((char*)buffer);

                    bufLength = GetFinalPathNameByHandle(SysHandleEx.ToSafeFileHandle(), fullName, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);
                }
                return fullName.ToString();
            }
            else
            {
                int error = Marshal.GetLastWin32Error();
                const int ERROR_PATH_NOT_FOUND = 3;
                const int ERROR_NOT_ENOUGH_MEMORY = 8;
                const int ERROR_INVALID_PARAMETER = 87; // 0x57

                /* Hold up. Let's free our memory before throwing exceptions. */
                Marshal.FreeHGlobal(buffer);

                throw error switch
                {
                    ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{fullName}' was not found when querying a file handle.", fileName: fullName.ToString()), // Removable storage, deleted item, network shares, et cetera
                    ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation."), // unlikely, but possible if system has little free memory
                    ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags."), // possible only if FILE_NAME_NORMALIZED (0) is invalid
                    _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path."),
                };
            }
        }
    }

    #endregion Classes
}
