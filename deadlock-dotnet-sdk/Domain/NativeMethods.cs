using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using deadlock_dotnet_sdk.Exceptions;
using Microsoft.Win32.SafeHandles;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.RestartManager;
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
internal static partial class NativeMethods
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

                // todo: new RmStartSession overload in CsWin32_NativeMethods.cs which can throw a StartSessionException derived from System.ComponentModel.Win32Exception
                // Why? <c>new Win32Exception()</c> will get the last PInvoke error code in addition to the system's message for that Win32ErrorCode.
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

                    // "using" blocks have hidden "finally" blocks which are executed before exceptions leave this context.
                    using (PWSTR pResources = (char*)Marshal.StringToHGlobalUni(path))
                    {
                        res = RmRegisterResources(handle, new Span<PWSTR>(new PWSTR[] { pResources }), rgApplications: new(), new());

                        if (res != 0)
                        {
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
                                        if (rethrowExceptions) throw;
                                    }
                                }
                            }
                            else
                            {
                                throw new RmListException();
                            }
                        }
                        else if (res != 0)
                        {
                            throw new UnauthorizedAccessException();
                        }
                    }
                }
                finally
                {
                    _ = RmEndSession(handle);
                }

                return processes;
            }
        }
    }

    /// <summary>
    ///     Query the system's open handles;
    ///     Try to filter them to just files, optionally including handles for non-File and unidentified object types;
    ///     Filter "File" handles to only those whose full paths contain the query string.
    /// </summary>
    /// <param name="query">
    ///     When a query string is passed to this method, all "File"
    ///     object handles will be filtered for only those whose full
    ///     paths contain this query string.
    /// </param>
    /// <param name="filter">
    ///     By default, this method only returns handles for objects
    ///     successfully identified as a file/directory ("File").
    ///     <see cref="Filter.NonFiles"/> and <see cref="Filter.TypeQueryFailed"/>
    /// </param>
    /// <returns>
    ///     A list of SafeFileHandleEx objects.
    ///     When requested, handles for non-file or unidentified objects will be included with file-specific properties nulled.
    /// </returns>
    /// <remarks>This might be arduously slow...</remarks>
    // TODO: Perhaps we should allow a new query without re-calling GetSystemHandleInfoEx().
    internal static List<SafeFileHandleEx> FindLockingHandles(string? query = null, Filter filter = Filter.FilesOnly)
    {
        Process.EnterDebugMode(); // just in case

        List<SafeFileHandleEx>? handles = GetSystemHandleInfoEx().ToArray().Cast<SafeFileHandleEx>().ToList();
        handles.RemoveAll(item => Discard(h: item));
        handles.Sort((a, b) => a.ProcessId.CompareTo(b.ProcessId));
        return handles;

        bool Discard(SafeFileHandleEx h)
        {
            if (h.HandleObjectType is not null)
            {
                /* Query for object type succeeded and the type is NOT File */
                if (h.HandleObjectType != "File")
                {
                    return !filter.HasFlag(Filter.NonFiles); // When requested, keep non-File object handle. Else, discard.
                }
                // Discard handle if Query and file's path are not null and file's path does not contain query */
                return (query is not null) && (h.FileFullPath is not null) && (!h.FileFullPath.Contains(query.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)));
            }
            else
            {
                return !filter.HasFlag(Filter.TypeQueryFailed); // When requested, keep handle if the object type query failed. Else, discard.
            }
        }
    }

    /// <summary>
    /// Filters for <see cref="FindLockingHandles(string?, Filter)"/>
    /// </summary>
    [Flags]
    internal enum Filter
    {
        FilesOnly = 0,
        NonFiles = 1,
        TypeQueryFailed = 2
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
#pragma warning disable RCS1213
        private readonly uint Reserved; // Remove unused field declaration. csharp(RCS1213) | Roslynator
#pragma warning restore RCS1213

        /// <summary>
        /// Get the Type of the object as a string
        /// </summary>
        /// <exception cref="Exception">P/Invoke function NtQueryObject failed. See Exception data.</exception>
        /// <returns>The Type of the object as a string.</returns>
        public unsafe string GetHandleObjectType()
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
                throw new Exception("P/Invoke function NtQueryObject failed. See Exception data.", status.GetNTStatusException());
            }
            return typeName;
        }

        /// <summary>Invokes <see cref="GetHandleObjectType()"/> and checks if the result is "File".</summary>
        /// <returns>True if the handle is for a file or directory.</returns>
        /// <remarks>Based on source of C/C++ projects <see href="https://www.x86matthew.com/view_post?id=hijack_file_handle">Hijack File Handle</see> and <see href="https://github.com/adamkramer/handle_monitor">Handle Monitor</see></remarks>
        /// <exception cref="Exception">Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. See InnerException for details.</exception>
        public bool IsFileHandle()
        {
            try
            {
                string type = GetHandleObjectType();
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
}
