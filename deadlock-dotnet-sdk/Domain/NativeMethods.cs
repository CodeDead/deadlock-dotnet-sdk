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
    #endregion Structs
    #region Classes
    #endregion Classes
}
