using System.Diagnostics;
using System.Runtime.InteropServices;
using deadlock_dotnet_sdk.Exceptions;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.RestartManager;
using Windows.Win32.System.WindowsProgramming;
using static deadlock_dotnet_sdk.Domain.FileLockerEx;
using static Windows.Win32.PInvoke;
using Code = PInvoke.NTSTATUS.Code;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;
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
    /// <exception cref="StartSessionException">Failed to start Restart Manager session. See InnerException for details.</exception>
    /// <exception cref="RegisterResourceException">Failed to register resources to the Restart Manager session. See InnerException for details.</exception>
    /// <exception cref="RmListException">Failed to get list of applications and services that are currently using the resources registered with the Restart Manager session. See InnerException for details.</exception>
    /// <exception cref="UnauthorizedAccessException">Failed to get list of applications and services that are currently using the resources registered with the Restart Manager session. See InnerException for details.</exception>
    internal static unsafe IEnumerable<Process> FindLockingProcesses(string path, bool rethrowExceptions)
    {
        using PWSTR key = new((char*)Marshal.StringToHGlobalUni(Guid.NewGuid().ToString()));
        List<Process> processes = new();

        Win32ErrorCode res = (Win32ErrorCode)RmStartSession(out uint handle, key);
        if (res != 0)
            throw new StartSessionException("Failed to start Restart Manager session.", new PInvoke.Win32Exception(res));

        try
        {
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = RmRebootReasonNone;

            string[] resources = { path };

            // "using" blocks have hidden "finally" blocks which are executed before exceptions leave this context.
            using PWSTR pResources = (char*)Marshal.StringToHGlobalUni(path);

            if ((res = (Win32ErrorCode)RmRegisterResources(handle, new Span<PCWSTR>(new PCWSTR[] { pResources }), rgApplications: new(), new()))
                is not Win32ErrorCode.ERROR_SUCCESS)
            {
                throw new RegisterResourceException("Failed to register resources to the Restart Manager session.", new PInvoke.Win32Exception(res));
            }

            if ((res = (Win32ErrorCode)RmGetList(handle, out var pnProcInfoNeeded, ref pnProcInfo, null, out lpdwRebootReasons))
                is Win32ErrorCode.ERROR_MORE_DATA)
            {
                ReadOnlySpan<RM_PROCESS_INFO> processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                pnProcInfo = pnProcInfoNeeded;

                fixed (RM_PROCESS_INFO* pProcessInfo = processInfo)
                    res = (Win32ErrorCode)RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, pProcessInfo, out lpdwRebootReasons);
                if (res is Win32ErrorCode.ERROR_SUCCESS)
                {
                    processes = new List<Process>((int)pnProcInfo);

                    for (int i = 0; i < pnProcInfo; i++)
                    {
                        try
                        {
                            processes.Add(Process.GetProcessById((int)processInfo[i].Process.dwProcessId));
                        }
                        catch (ArgumentException) when (!rethrowExceptions)
                        { }
                    }
                }
                else
                {
                    throw new RmListException("Failed to get list of applications and services that are currently using the resources registered with the Restart Manager session.", new PInvoke.Win32Exception(res));
                }
            }
            else if (res is not Win32ErrorCode.ERROR_SUCCESS)
            {
                throw new UnauthorizedAccessException("Failed to get list of applications and services that are currently using the resources registered with the Restart Manager session.", new PInvoke.Win32Exception(res));
            }
        }
        finally
        {
            _ = RmEndSession(handle);
        }

        return processes;
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
    ///     By default, this method only returns handles for objects successfully identified as a File.
    ///     File objects' sub-type can be Directory, File, "File or Directory", Network, Other, or Pipe.
    /// </param>
    /// <returns>
    ///     A list of SafeFileHandleEx objects. When requested, handles for non-file or unidentified objects will be included with file-specific properties nulled.
    /// </returns>
    /// TODO: optimize process inspection. Stuff like IsProcessProtected should only be queried once per process
    internal static List<ProcessInfo> FindLockingHandles(string query, HandlesFilter filter = HandlesFilter.FilesOnly)
    {
        List<ProcessInfo> processes = Process
            .GetProcesses()
            .ToList()
            .ConvertAll(p => new ProcessInfo(p));
        var handles = GetSystemHandleInfoEx()
            .ToArray()
            .GroupBy(h => h.UniqueProcessId);
        var sw = Stopwatch.StartNew();

        var results = Parallel.ForEach(processes, p =>
        {
            var match = handles.FirstOrDefault(group => (int)group.Key == p.Process.Id);
            if (match is not null)
                p.Handles.AddRange(match.ToList().ConvertAll<SafeFileHandleEx>(h => new(h)).Where(h => keep(h)));
            else
                return;
        });

        processes.Sort((a, b) => a.Process.Id.CompareTo(b.Process.Id));
        sw.Stop();
        Console.WriteLine("FindLockingHandles time elapsed: " + sw.Elapsed);

        //return handles;
        return processes;

        bool keep(SafeFileHandleEx h)
        {
            bool keep = false;

            if (!string.IsNullOrEmpty(query))
            {
                // only keep if FullFilePath contains query (with normalized directory separators)
                string normalizedQuery = normalize(query);
                string normalizedFileNameInfo = h.FileNameInfo.v is not null ? normalize(h.FileNameInfo.v) : string.Empty;
                string normalizedFileFullPath = h.FileFullPath.v is not null ? normalize(h.FileFullPath.v) : string.Empty;

                /* If a handle is unrelated to the query, it doesn't matter. No other conditions matter at this point */
                // If an object name is returned by the system and it is null or zero-length, is it impossible for it to be a File handle?
                return (!string.IsNullOrEmpty(h.ObjectName.v) && h.ObjectName.v.Contains(normalizedQuery))
                       || (normalizedFileNameInfo.Length is not 0 && normalizedFileNameInfo.Contains(normalizedQuery))
                       || (normalizedFileFullPath.Length is not 0 && normalizedFileFullPath.Contains(normalizedQuery));

                string normalize(string s) => s is not null ? s.ToLower().Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar) : string.Empty;
            }
            if (filter is HandlesFilter.FilesOnly)
            {
                // only keep if handle object is 'File'
                // note: File objects' sub-type can be Directory, File, "File or Directory", Network, Other, or Pipe.
                return h.IsFileHandle.v is not true; // query failed or object is not a File
            }

            /* Check combined filters in reverse order */
            if (!keep && filter.HasFlag(HandlesFilter.IncludeProtectedProcesses))
            {
                // if a process is protected, do not discard the handle
                keep = h.ProcessIsProtected.v is true;
            }
            if (!keep && filter.HasFlag(HandlesFilter.IncludeNonFiles))
            {
                // keep if object type query succeeded
                keep = !string.IsNullOrWhiteSpace(h.HandleObjectType.v);
            }
            if (!keep && filter.HasFlag(HandlesFilter.IncludeFailedTypeQuery))
            {
                keep = string.IsNullOrWhiteSpace(h.HandleObjectType.v);
            }

            return keep;
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

        for (uint attempts = 0; status.Code is Code.STATUS_INFO_LENGTH_MISMATCH && attempts < 10; attempts++)
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

        if (status != Code.STATUS_SUCCESS)
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
                )) == Code.STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal((IntPtr)pSysInfoBuffer);
                systemInformationLength *= 2;

                // Fail if we're resizing the buffer to something very large.
                if (systemInformationLength > PH_LARGE_BUFFER_SIZE)
                    throw new NTStatusException(Code.STATUS_BUFFER_OVERFLOW);

                pSysInfoBuffer = (SYSTEM_HANDLE_INFORMATION_EX*)Marshal.ReAllocHGlobal(pv: (IntPtr)pSysInfoBuffer, cb: (IntPtr)systemInformationLength);
            }
        }

        if (status != Code.STATUS_SUCCESS)
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
