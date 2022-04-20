using System.Diagnostics;
using System.Runtime.InteropServices;
using deadlock_dotnet_sdk.Exceptions;

namespace deadlock_dotnet_sdk.Domain
{
    /// <summary>
    /// Collection of native methods
    /// </summary>
    internal static class NativeMethods
    {
        #region Variables

        private const int RmRebootReasonNone = 0;
        private const int CchRmMaxAppName = 255;
        private const int CchRmMaxSvcName = 63;

        #endregion

        #region Enum_Struct

        [StructLayout(LayoutKind.Sequential)]
        private struct RmUniqueProcess
        {
            internal readonly int dwProcessId;
            private readonly System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        private enum RmAppType
        {
            // ReSharper disable once UnusedMember.Local
            RmUnknownApp = 0,

            // ReSharper disable once UnusedMember.Local
            RmMainWindow = 1,

            // ReSharper disable once UnusedMember.Local
            RmOtherWindow = 2,

            // ReSharper disable once UnusedMember.Local
            RmService = 3,

            // ReSharper disable once UnusedMember.Local
            RmExplorer = 4,

            // ReSharper disable once UnusedMember.Local
            RmConsole = 5,

            // ReSharper disable once UnusedMember.Local
            RmCritical = 1000
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct RmProcessInfo
        {
            internal RmUniqueProcess Process;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxAppName + 1)]
            private readonly string strAppName;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CchRmMaxSvcName + 1)]
            private readonly string strServiceShortName;

            private readonly RmAppType ApplicationType;
            private readonly uint AppStatus;
            private readonly uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] private readonly bool bRestartable;
        }

        #endregion

        #region DllImport

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
            uint nApplications, [In] RmUniqueProcess[] rgApplications, uint nServices, string[] rgsServiceNames);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint pSessionHandle);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
            [In, Out] RmProcessInfo[] rgAffectedApps, ref uint lpdwRebootReasons);

        #endregion

        /// <summary>
        /// Find the processes that are locking a file
        /// </summary>
        /// <param name="path">Path to the file</param>
        /// <param name="rethrowExceptions">True if inner exceptions should be rethrown, otherwise false</param>
        /// <returns>A collection of processes that are locking a file</returns>
        internal static IEnumerable<Process> FindLockingProcesses(string path, bool rethrowExceptions)
        {
            string key = Guid.NewGuid().ToString();
            List<Process> processes = new();

            int res = RmStartSession(out var handle, 0, key);
            if (res != 0)
            {
                throw new StartSessionException();
            }

            try
            {
                const int errorMoreData = 234;
                uint pnProcInfo = 0;
                uint lpdwRebootReasons = RmRebootReasonNone;

                string[] resources = {path};
                res = RmRegisterResources(handle, (uint) resources.Length, resources, 0, null, 0, null);

                if (res != 0)
                {
                    throw new RegisterResourceException();
                }

                res = RmGetList(handle, out var pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

                if (res == errorMoreData)
                {
                    RmProcessInfo[] processInfo = new RmProcessInfo[pnProcInfoNeeded];
                    pnProcInfo = pnProcInfoNeeded;

                    res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                    if (res == 0)
                    {
                        processes = new List<Process>((int) pnProcInfo);

                        for (int i = 0; i < pnProcInfo; i++)
                        {
                            try
                            {
                                processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                            }
                            catch (ArgumentException)
                            {
                                if (rethrowExceptions) throw;
                            }
                        }
                    }
                    else throw new RmListException();
                }
                else if (res != 0) throw new UnauthorizedAccessException();
            }
            finally
            {
                _ = RmEndSession(handle);
            }

            return processes;
        }
    }
}
