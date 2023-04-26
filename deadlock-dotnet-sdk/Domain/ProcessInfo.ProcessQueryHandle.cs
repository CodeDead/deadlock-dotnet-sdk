using Microsoft.Win32.SafeHandles;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;
using Win32Exception = System.ComponentModel.Win32Exception;

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
        /// <exception cref="Win32Exception">Failed to open handle. The process might not exist, access was denied, or an unknown error occurred.<br/>
        ///     <example>
        ///     If processId is 0, error code is ERROR_INVALID_PARAMETER<br/>
        ///     If process is System (4), CRSS, or similarly protected processes, error code is ERROR_ACCESS_DENIED<br/>
        ///     </example>
        /// </exception>
        /// <remarks>
        /// - If processId == Process.GetCurrentProcess().Id, use Process.GetCurrentProcess().SafeHandle property instead.
        /// - If Windows.Win32.PInvoke.IsDebugModeEnabled() == true, the requested access is granted regardless of the security descriptor. See GetSecurityInfo();
        /// </remarks>
        public static ProcessQueryHandle OpenProcessHandle(int processId, PROCESS_ACCESS_RIGHTS accessRights)
        {
            var h = OpenProcess_SafeHandle(accessRights, false, (uint)processId);
            return h is null ? throw new Win32Exception() : (new(h, accessRights));
        }

        public static implicit operator SafeProcessHandle(ProcessQueryHandle v) => v.Handle;
    }
}
