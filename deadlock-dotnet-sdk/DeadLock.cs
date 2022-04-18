using System.Diagnostics;
using deadlock_dotnet_sdk.Domain;

namespace deadlock_dotnet_sdk
{
    public class DeadLock
    {
        #region Properties

        /// <summary>
        /// Property that specifies whether inner exceptions should be rethrown or not
        /// </summary>
        public bool RethrowExceptions { get; set; }

        #endregion

        /// <summary>
        /// Default constructor
        /// </summary>
        public DeadLock()
        {
            // Default constructor
        }

        /// <summary>
        /// Initialize a new DeadLock
        /// </summary>
        /// <param name="rethrowExceptions">True if inner exceptions should be rethrown, otherwise false</param>
        public DeadLock(bool rethrowExceptions)
        {
            RethrowExceptions = rethrowExceptions;
        }

        /// <summary>
        /// Retrieve the FileLocker object that contains a List of Process objects that are locking a file
        /// </summary>
        /// <param name="filePath">The full path of a file</param>
        /// <returns>The FileLocker object that contains a List of Process objects that are locking a file</returns>
        public FileLocker FindLockingProcesses(string filePath)
        {
            FileLocker fileLocker = new(filePath, NativeMethods.FindLockingProcesses(filePath, RethrowExceptions).ToList());
            return fileLocker;
        }

        /// <summary>
        /// Retrieve the List of FileLocker objects for one or multiple files
        /// </summary>
        /// <param name="filePaths">The full path of a file</param>
        /// <returns>The List of FileLocker objects that contain the processes that are locking a file</returns>
        public List<FileLocker> FindLockingProcesses(params string[] filePaths)
        {
            List<FileLocker> fileLockers = new();
            foreach (string filePath in filePaths)
            {
                fileLockers.Add(FindLockingProcesses(filePath));
            }

            return fileLockers;
        }

        /// <summary>
        /// Retrieve the FileLocker object that contains a List of Process objects that are locking a file asynchronously
        /// </summary>
        /// <param name="filePath">The full path of a file</param>
        /// <returns>The FileLocker object that contains a List of Process objects that are locking a file</returns>
        public async Task<FileLocker> FindLockingProcessesAsync(string filePath)
        {
            FileLocker fileLocker = new();

            await Task.Run(() =>
            {
                fileLocker = new FileLocker(filePath, NativeMethods.FindLockingProcesses(filePath, RethrowExceptions).ToList());
            });

            return fileLocker;
        }

        /// <summary>
        /// Retrieve the List of FileLocker objects for one or multiple files asynchronously
        /// </summary>
        /// <param name="filePaths">The full path of a file</param>
        /// <returns>The List of FileLocker objects that contain the processes that are locking a file</returns>
        public async Task<List<FileLocker>> FindLockingProcessesAsnyc(params string[] filePaths)
        {
            List<FileLocker> fileLockers = new();

            await Task.Run(() =>
            {
                foreach (string filePath in filePaths)
                {
                    fileLockers.Add(new FileLocker(filePath, NativeMethods.FindLockingProcesses(filePath, RethrowExceptions).ToList()));
                }
            });

            return fileLockers;
        }

        /// <summary>
        /// Unlock a File by killing all the processes that are holding a handle on the file
        /// </summary>
        /// <param name="fileLocker">The FileLocker that contains the List of Process objects that should be killed</param>
        public void Unlock(FileLocker fileLocker)
        {
            foreach (Process p in fileLocker.Lockers)
            {
                if (p.HasExited) continue;
                p.Kill();
                p.WaitForExit();
            }
        }

        /// <summary>
        /// Unlock one or more files by killing all the processes that are holding a handle on the files 
        /// </summary>
        /// <param name="fileLockers">The FileLocker objects that contain the List of Process objects that are locking a file</param>
        public void Unlock(params FileLocker[] fileLockers)
        {
            foreach (FileLocker fileLocker in fileLockers)
            {
                Unlock(fileLocker);
            }
        }

        /// <summary>
        /// Unlock a File asynchronously by killing all the processes that are holding a handle on the file
        /// </summary>
        /// <param name="fileLocker">The FileLocker that contains the List of Process objects that should be killed</param>
        public async void UnlockAsync(FileLocker fileLocker)
        {
            await Task.Run(() =>
            {
                foreach (Process p in fileLocker.Lockers)
                {
                    if (p.HasExited) continue;
                    p.Kill();
                    p.WaitForExit();
                }
            });
        }

        /// <summary>
        /// Unlock one or more files asynchronously by killing all the processes that are holding a handle on the files 
        /// </summary>
        /// <param name="fileLockers">The FileLocker objects that contain the List of Process objects that are locking a file</param>
        public async void UnlockAsync(params FileLocker[] fileLockers)
        {
            await Task.Run(() =>
            {
                foreach (FileLocker fileLocker in fileLockers)
                {
                    foreach (Process p in fileLocker.Lockers)
                    {
                        if (p.HasExited) continue;
                        p.Kill();
                        p.WaitForExit();
                    }
                }
            });
        }
    }
}
