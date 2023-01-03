using System.Diagnostics;
using System.Runtime.InteropServices;
using deadlock_dotnet_sdk.Exceptions;
using PInvoke;
using Windows.Win32.Foundation;
using Windows.Win32.System.RestartManager;
using Windows.Win32.System.WindowsProgramming;
using static deadlock_dotnet_sdk.Domain.FileLockerEx;
using static Windows.Win32.PInvoke;
using NTSTATUS = PInvoke.NTSTATUS;
using Win32Exception = System.ComponentModel.Win32Exception;

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
    ///     Query the system's open handles, optionally including non-file handles or handles whose types could not be determined.
    /// </summary>
    /// <param name="query">
    ///     When a query string is passed to this method, all "File"
    ///     object handles will be filtered for only those whose full
    ///     paths contain this query string.
    /// </param>
    /// <param name="filter">
    ///     By default, this method only returns handles for objects
    ///     successfully identified as a file/directory ("File").
    ///     <see cref="HandlesFilter.IncludeNonFiles"/> and <see cref="HandlesFilter.IncludeFailedTypeQuery"/>
    /// </param>
    /// <returns>
    ///     A list of SafeFileHandleEx objects.
    ///     When requested, handles for non-file or unidentified objects will be included with file-specific properties nulled.
    /// </returns>
    /// <remarks><see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege">SeDebugMode</see> may be required for data from system and service processes. Restart app as admin and call <see cref="Process.EnterDebugMode"</see>.</remarks>
    // TODO: Perhaps we should allow a new query without re-calling GetSystemHandleInfoEx().
    internal static List<SafeFileHandleEx> FindLockingHandles(string? query = null, HandlesFilter filter = HandlesFilter.FilesOnly)
    {
        List<SafeFileHandleEx>? handles = new();

        foreach (var h in GetSystemHandleInfoEx())
        {
            handles.Add(new SafeFileHandleEx(h));
        }

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
                    return !filter.HasFlag(HandlesFilter.IncludeNonFiles); // When requested, keep non-File object handle. Else, discard.
                }
                // Discard handle if Query and file's path are not null and file's path does not contain query */
                return (query is not null) && (h.FileFullPath is not null) && (!h.FileFullPath.Contains(query.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar)));
            }
            else
            {
                return !filter.HasFlag(HandlesFilter.IncludeFailedTypeQuery); // When requested, keep handle if the object type query failed. Else, discard.
            }
        }
    }

    /// <summary>
    /// Get a Span of <see cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"/> via <see cref="NtQuerySystemInformation"/>
    /// </summary>
    /// <remarks>Heavily influenced by ProcessHacker/SystemInformer</remarks>
    /// <exception cref="NTStatusException"></exception>
    /// <exception cref="Win32Exception"></exception>
    internal unsafe static ReadOnlySpan<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> GetSystemHandleInfoEx()
    {
        const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        const uint PH_LARGE_BUFFER_SIZE = 256 * 1024 * 1024; // 256 Mebibytes
        uint systemInformationLength = (uint)Marshal.SizeOf<SYSTEM_HANDLE_INFORMATION_EX>();
        SYSTEM_HANDLE_INFORMATION_EX* pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.AllocHGlobal(Marshal.SizeOf<SYSTEM_HANDLE_INFORMATION_EX>());
        uint returnLength = 0;

        NTSTATUS status = NtQuerySystemInformation(
            SystemInformationClass: SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
            SystemInformation: pSysInfoBuffer,
            SystemInformationLength: systemInformationLength,
            ReturnLength: ref returnLength
            );

        for (uint attempts = 0; status.Value == NTSTATUS.Code.STATUS_INFO_LENGTH_MISMATCH && attempts < 10; attempts++)
        {
            /** The value of returnLength depends on how many handles are open.
             Handles may be opened or closed before, during, and after this operation, so the return length is rarely correct.
              */
            systemInformationLength = (uint)(returnLength * 1.5);
            pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.ReAllocHGlobal((IntPtr)pSysInfoBuffer, (IntPtr)systemInformationLength);

            status = NtQuerySystemInformation(
                SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                pSysInfoBuffer,
                systemInformationLength,
                ref returnLength
                );
        }

        if (status != NTSTATUS.Code.STATUS_SUCCESS)
        {
            // Fall back to using the previous code that we've used since Windows XP (dmex)
            systemInformationLength = 0x10000;
            //Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
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
                    throw new NTStatusException(NTSTATUS.Code.STATUS_BUFFER_OVERFLOW);

                pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.ReAllocHGlobal(pv: (IntPtr)pSysInfoBuffer, cb: (IntPtr)systemInformationLength);
            }
        }

        if (status != NTSTATUS.Code.STATUS_SUCCESS)
        {
            Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
            throw new NTStatusException(status);
        }

        var retVal = (*pSysInfoBuffer).AsSpan();

        Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);

        return retVal;
    }

    #endregion Methods
}
