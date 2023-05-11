using Microsoft.Win32.SafeHandles;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;

namespace deadlock_dotnet_sdk.Domain;

public partial class ProcessInfo
{
    public class ProcessQueryHandle
    {
        public ProcessQueryHandle(SafeProcessHandle processHandle, PROCESS_ACCESS_RIGHTS accessRights)
        {
            Handle = processHandle;
            AccessRights = accessRights;
        }

        public SafeProcessHandle Handle { get; }
        public PROCESS_ACCESS_RIGHTS AccessRights { get; }

        /// <summary>
        /// Open a handle with the requested rights for a process.
        /// </summary>
        /// <param name="processId"></param>
        /// <param name="accessRights"></param>
        /// <returns>A ProcessQueryHandle wrapping a SafeProcessHandle and the requested access rights.</returns>
        /// <exception cref="UnauthorizedAccessException">Failed to open process (ID <paramref name="processId"/>) with access rights '<paramref name="accessRights"/>'.</exception>
        /// <exception cref="ArgumentException">Cannot open handle for process (ID <paramref name="processId"/>).</exception>
        /// <exception cref="Exception">Unrecognized error occurred when attempting to open handle for process with ID <paramref name="processId"/>.</exception>
        /// <remarks>
        /// - If processId == Process.GetCurrentProcess().Id, use Process.GetCurrentProcess().SafeHandle property instead.
        /// - If Windows.Win32.PInvoke.IsDebugModeEnabled() is true, the requested access is granted regardless of the security descriptor. See GetSecurityInfo();
        /// </remarks>
        public static ProcessQueryHandle OpenProcessHandle(int processId, PROCESS_ACCESS_RIGHTS accessRights)
            => new(OpenProcess_SafeHandle(accessRights, false, (uint)processId), accessRights);

        public static implicit operator SafeProcessHandle(ProcessQueryHandle v) => v.Handle;
    }
}
