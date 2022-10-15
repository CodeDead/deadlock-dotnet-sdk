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
        /// TODO:
        /// </summary>
        /// <param name="path">The path of the file or directory</param>
        /// <param name="filter"></param>
        public FileLockerEx(string path, ResultsFilter filter)
        {
            Path = path;
            Lockers = NativeMethods.FindLockingHandles(path, filter);
        }

        /// <summary>
        /// Filters for <see cref="NativeMethods.FindLockingHandles(string?, ResultsFilter)"/>
        /// </summary>
        /// TODO: rename to HandlesFilter
        [Flags]
        public enum ResultsFilter
        {
            FilesOnly = 0,
            IncludeNonFiles = 1,
            IncludeFailedTypeQuery = 2
        }
    }
}
