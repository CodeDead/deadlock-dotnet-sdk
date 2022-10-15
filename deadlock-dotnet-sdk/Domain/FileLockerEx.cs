namespace deadlock_dotnet_sdk.Domain
{
    public class FileLockerEx
    {
        #region Properties

        /// <summary>
        /// Get or set the path of the file that is locked
        public string Path { get; set; }

        /// <summary>
        /// Get or set the List of Process objects that are locking the file
        /// </summary>
        public List<SafeHandleEx> Lockers { get; set; }

        #endregion

        /// <summary>
        /// Initialize a new FileLocker
        /// </summary>
        public FileLockerEx()
        {
            Path = "";
            Lockers = new List<SafeHandleEx>();
        }

        /// <summary>
        /// Initialize a new FileLocker
        /// </summary>
        /// <param name="path">The path of the file</param>
        /// <param name="lockers">The List of Process objects that are locking the file</param>
        public FileLockerEx(string path, List<SafeHandleEx> lockers)
        {
            Path = path;
            Lockers = lockers;
        }

        public static FileLockerEx GetFileLockerEx(string path, NativeMethods.Filter filter)
        {
            return new(
                path,
                NativeMethods.FindLockingHandles(path, filter)
                );
        }
    }
}
