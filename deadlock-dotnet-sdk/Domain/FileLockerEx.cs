using System.ComponentModel;
using System.Text;

namespace deadlock_dotnet_sdk.Domain
{
    //TODO: Add RefreshList(). This should clear Lockers and call FindLockingHandles again.
    //TODO: If a handle is closed or invalid, remove if from Lockers. SafeHandle.IsClosed is unreliable—it only works on handles managed by the current process.
    //TODO: feat: finalize OrderBy parameters
    //https://sourcegraph.com/github.com/dotnet/runtime@main/-/blob/src/libraries/System.Private.CoreLib/src/System/Runtime/InteropServices/SafeHandle.cs
    public class FileLockerEx
    {
        private List<SafeFileHandleEx> lockers;
        #region Properties

        /// <summary>A keyphrase or the full or partial path of the locked file.</summary>
        public string Path { get; }
        public HandlesFilter Filter { get; }

        public SortByProperty SortByPrimary { get; set; } = SortByProperty.ProcessId;
        public SortByProperty SortBySecondary { get; set; } = SortByProperty.ObjectRealName;

        /// <summary>Used by the user to choose the primary and secondary sortation orders i.e. sort by process id and then by handle value</summary>
        public enum SortByProperty
        {
            /// <summary>NOT IMPLEMENTED</summary>
            FileShareAccess, // oh, this is important! Note: System Informer seems to crash when evaluating this property // TODO: implement FileShareAccess property
            HandleAttributes,
            HandleSubType,
            HandleType,
            HandleValue,
            GrantedAccessHexadecimal,
            GrantedAccessSymbolic,
            /// <summary>The string returned to the ObjectName property via NtQueryObject.</summary>
            ObjectOriginalName,
            /// <summary>
            /// (NOT IMPLEMENTED)
            /// Differs from ObjectName for types {File, (Registry) Key}
            /// </summary>
            /// TODO: get 'real' paths e.g. "\REGISTRY\MACHINE" -> "HKLM"
            ObjectRealName,
            ObjectAddress,
            ProcessId
        }

        // TODO: order by Process ID and then by handle value. Later todo: allow user-specified sorting rule (e.g. by column/property)
        /// <summary>Get or set the List of handles that are locking the file</summary>
        public List<SafeFileHandleEx> Lockers
        {
            get
            {
                return lockers
                    .OrderBy(h =>
                    {
                        switch (SortByPrimary) // returns byte[]
                        {
                            //case SortByProperty.FileShareAccess: return h.FileShareAccess; // not possible without a kernel mode driver; see IoCheckShareAccess
                            case SortByProperty.HandleAttributes: return Encoding.ASCII.GetBytes(h.HandleAttributes.ToString());
                            case SortByProperty.HandleSubType: return Encoding.ASCII.GetBytes(h.FileHandleType.v?.ToString() ?? string.Empty);
                            case SortByProperty.HandleType: return Encoding.ASCII.GetBytes(h.HandleObjectType.v?.ToString() ?? string.Empty);
                            case SortByProperty.HandleValue: return Encoding.ASCII.GetBytes(h.HandleValue.ToString());
                            case SortByProperty.GrantedAccessHexadecimal: return BitConverter.GetBytes(h.GrantedAccess.Value);
                            case SortByProperty.GrantedAccessSymbolic: return Encoding.ASCII.GetBytes(h.GrantedAccessString);
                            case SortByProperty.ObjectOriginalName: return Encoding.ASCII.GetBytes(h.ObjectName.v ?? string.Empty);
                            case SortByProperty.ObjectRealName: return Encoding.ASCII.GetBytes(h.FileFullPath.v ?? h.FileNameInfo.v ?? string.Empty); // TODO: implement Registry key parsing
                            case SortByProperty.ObjectAddress: return BitConverter.GetBytes((ulong)h.ObjectAddress);
                            case SortByProperty.ProcessId: return BitConverter.GetBytes(h.ProcessId);
                            default: goto case SortByProperty.ProcessId;
                        }
                    })
                    .ThenBy(h =>
                    {
                        switch (SortBySecondary) // returns byte[]
                        {
                            //case SortByProperty.FileShareAccess: return h.FileShareAccess; // not possible without a kernel mode driver; see IoCheckShareAccess
                            case SortByProperty.HandleAttributes: return Encoding.ASCII.GetBytes(h.HandleAttributes.ToString());
                            case SortByProperty.HandleSubType: return Encoding.ASCII.GetBytes(h.FileHandleType.v?.ToString() ?? string.Empty);
                            case SortByProperty.HandleType: return Encoding.ASCII.GetBytes(h.HandleObjectType.v?.ToString() ?? string.Empty);
                            case SortByProperty.HandleValue: return Encoding.ASCII.GetBytes(h.HandleValue.ToString());
                            case SortByProperty.GrantedAccessHexadecimal: return BitConverter.GetBytes(h.GrantedAccess.Value);
                            case SortByProperty.GrantedAccessSymbolic: return Encoding.ASCII.GetBytes(h.GrantedAccessString);
                            case SortByProperty.ObjectOriginalName: return Encoding.ASCII.GetBytes(h.ObjectName.v ?? string.Empty);
                            case SortByProperty.ObjectRealName: return Encoding.ASCII.GetBytes(h.FileFullPath.v ?? h.FileNameInfo.v ?? string.Empty); // TODO: implement Registry key parsing
                            case SortByProperty.ObjectAddress: return BitConverter.GetBytes((ulong)h.ObjectAddress);
                            case SortByProperty.ProcessId: return BitConverter.GetBytes(h.ProcessId);
                            default: goto case SortByProperty.ProcessId;
                        }
                    })
                    .ToList();
            }
        }

        #endregion Properties

        /// <summary>
        /// Initialize a new FileLocker
        /// </summary>
        public FileLockerEx()
        {
            Path = "";
            lockers = new();
        }

        /// <summary>
        /// Invoke QuerySystemInformationEx() to get SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        /// objects, optionally including handles of non-file and/or unidentified object types
        /// </summary>
        /// <param name="path">The path of the file or directory</param>
        /// <param name="filter">Include non-file handles and handles of unidentified object types.</param>
        /// <param name="rethrowExceptions">Assign True to rethrow exceptions</param>
        /// <param name="warningException">When not null, DeadLock failed to grant debug permissions to the current thread failed. See inner Exceptions for more information.</param>
        /// <exception cref="UnauthorizedAccessException">DeadLock was denied debug permissions to access system, service, and admin processes. By default, Administrators are allowed this permission. Try running as Administrator.</exception>
        /// <remarks>This constructor enables Debugger permissions for the current process. If the process is not running as admin, Debugger permissions may be denied and some functionality won't work as intended.</remarks>
        public FileLockerEx(string path, HandlesFilter filter, bool rethrowExceptions, out WarningException? warningException)
        {
            warningException = null;
            Path = path;
            Filter = filter;

            try
            {
                if (!Windows.Win32.PInvoke.IsDebugModeEnabled())
                    System.Diagnostics.Process.EnterDebugMode();
            }
            catch (Exception e)
            {
                var uae = new UnauthorizedAccessException("DeadLock failed to check if it already has Debug permission -OR- was denied debug permissions to access system, service, and admin processes. Some functionality won't work. For debug access, try running this app as Administrator.", e);
                if (rethrowExceptions)
                    throw uae;
                else
                    warningException = new("Failed to enable Debug Mode for greater access to processes which do not belong to the current user or admin.", uae);
            }

            lockers = NativeMethods.FindLockingHandles(path, filter);
        }

        /// <summary>
        /// Filters for <see cref="NativeMethods.FindLockingHandles(string?, HandlesFilter)"/>
        /// </summary>
        [Flags]
        public enum HandlesFilter
        {
            /// <summary>'File' objects have a sub-type (Directory, File, "File or Directory", Network, Other, Pipe)</summary>
            FilesOnly = 0,
            IncludeNonFiles = 1,
            IncludeFailedTypeQuery = 1 << 1,
            /// <summary>4 + IncludeFailedTypeQuery</summary>
            IncludeProtectedProcesses = (1 << 2) + IncludeFailedTypeQuery
        }

        /// <summary>Clear existing handles from list and query system for new list.</summary>
        public void Refresh()
        {
            lockers = NativeMethods.FindLockingHandles(Path, Filter);
        }
    }
}
