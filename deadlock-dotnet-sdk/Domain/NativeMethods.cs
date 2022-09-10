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
                            throw new RegisterResourceException();
                        }

                        res = RmGetList(handle, out var pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

                        if (res == errorMoreData)
                        {
                            RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                            pnProcInfo = pnProcInfoNeeded;

                            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                            if (res == 0)
                            {
                                processes = new List<Process>((int)pnProcInfo);

                                for (int i = 0; i < pnProcInfo; i++)
                                {
                                    try
                                    {
                                        processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                                    }
                                    catch (ArgumentException) when (!rethrowExceptions)
                                    {
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
    #endregion Methods

    #region Structs
    #endregion Structs
    #region Classes
    #endregion Classes
}
