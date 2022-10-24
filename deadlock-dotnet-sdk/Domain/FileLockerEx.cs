namespace deadlock_dotnet_sdk.Domain
{
    public class FileLockerEx
    {
        #region Properties

        /// <summary>
        /// Get or set the path of the file that is locked
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Get or set the List of handles that are locking the file
        /// </summary>
        public List<SafeFileHandleEx> Lockers { get; set; }

        #endregion Properties

        /// <summary>
        /// Initialize a new FileLocker
        /// </summary>
        public FileLockerEx()
        {
            Path = "";
            Lockers = new List<SafeFileHandleEx>();
        }

        /// <summary>
        /// Initialize a new FileLocker
        /// </summary>
        /// <param name="path">The path of the file or directory</param>
        /// <param name="lockers">The List of handles that are locking the file</param>
        public FileLockerEx(string path, List<SafeFileHandleEx> lockers)
        {
            Path = path;
            Lockers = lockers;
        }

        /// <summary>
        /// Invoke QuerySystemInformationEx() to get SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        /// objects, optionally including handles of non-file and/or unidentified object types
        /// </summary>
        /// <param name="path">The path of the file or directory</param>
        /// <param name="filter">Include non-file handles and handles of unidentified object types. Default: Files Only</param>
        /// <param name="rethrowExceptions">Assign True to rethrow exceptions</param>
        /// <exception cref="UnauthorizedAccessException">DeadLock was denied debug permissions to access system, service, and admin processes. By default, Administrators are allowed this permission. Try running as Administrator.</exception>
        public FileLockerEx(string path, HandlesFilter filter, bool rethrowExceptions = false)
        {
            Path = path;

            try
            {
                System.Diagnostics.Process.EnterDebugMode();
            }
            catch (Exception e)
            {
                if (rethrowExceptions)
                    throw new UnauthorizedAccessException("DeadLock was denied debug permissions to access system, service, and admin processes. For debug access, try running this app as Administrator or contact your technician.", e);
            }

            Lockers = NativeMethods.FindLockingHandles(path, filter);
        }

        /// <summary>
        /// Filters for <see cref="NativeMethods.FindLockingHandles(string?, HandlesFilter)"/>
        /// </summary>
        /// TODO: rename to HandlesFilter
        [Flags]
        public enum HandlesFilter
        {
            FilesOnly = 0,
            IncludeNonFiles = 1,
            IncludeFailedTypeQuery = 2
        }
    }
}
