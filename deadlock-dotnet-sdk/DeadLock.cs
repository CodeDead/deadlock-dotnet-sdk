using System.ComponentModel;
using System.Diagnostics;
using deadlock_dotnet_sdk.Domain;
using HandlesFilter = deadlock_dotnet_sdk.Domain.FileLockerEx.HandlesFilter;

namespace deadlock_dotnet_sdk
{
    public class DeadLock
    {
        #region Properties

        /// <summary>
        /// Property that specifies whether inner exceptions should be rethrown or not
        /// </summary>
        public bool RethrowExceptions { get; set; }

        #endregion Properties

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

        #region ProcessLocks

        /// <summary>
        /// Retrieve the FileLocker object that contains a List of Process objects that are locking a file
        /// </summary>
        /// <param name="filePath">The full path of a file</param>
        /// <returns>The FileLocker object that contains a List of Process objects that are locking a file</returns>
        public FileLocker FindLockingProcesses(string filePath)
        {
            return new(filePath,
                NativeMethods.FindLockingProcesses(filePath, RethrowExceptions).ToList());
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
                fileLocker = new FileLocker(filePath,
                    NativeMethods.FindLockingProcesses(filePath, RethrowExceptions).ToList());
            });

            return fileLocker;
        }

        /// <summary>
        /// Retrieve the List of FileLocker objects for one or multiple files asynchronously
        /// </summary>
        /// <param name="filePaths">The full path of a file</param>
        /// <returns>The List of FileLocker objects that contain the processes that are locking a file</returns>
        public async Task<List<FileLocker>> FindLockingProcessesAsync(params string[] filePaths)
        {
            List<FileLocker> fileLockers = new();

            await Task.Run(() =>
            {
                foreach (string filePath in filePaths)
                {
                    fileLockers.Add(new FileLocker(filePath,
                        NativeMethods.FindLockingProcesses(filePath, RethrowExceptions).ToList()));
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
        public async Task UnlockAsync(FileLocker fileLocker)
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
        public async Task UnlockAsync(params FileLocker[] fileLockers)
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

        /// <summary>
        /// Unlock a file without retrieving the List of FileLocker objects
        /// </summary>
        /// <param name="filePath">The path of the file that should be unlocked</param>
        public void Unlock(string filePath)
        {
            FileLocker fileLocker = FindLockingProcesses(filePath);
            Unlock(fileLocker);
        }

        /// <summary>
        /// Unlock a file without retrieving the List of FileLocker objects asynchronously
        /// </summary>
        /// <param name="filePath">The path of the file that should be unlocked</param>
        public async Task UnlockAsync(string filePath)
        {
            FileLocker locker = await FindLockingProcessesAsync(filePath);
            await UnlockAsync(locker);
        }

        /// <summary>
        /// Unlock one or more files without retrieving the List of FileLocker objects
        /// </summary>
        /// <param name="filePaths">The full paths of the files that should be unlocked</param>
        public void Unlock(params string[] filePaths)
        {
            List<FileLocker> fileLockers = FindLockingProcesses(filePaths);

            foreach (FileLocker fileLocker in fileLockers)
            {
                Unlock(fileLocker);
            }
        }

        /// <summary>
        /// Unlock one or more files without retrieving the List of FileLocker objects asynchronously
        /// </summary>
        /// <param name="filePaths">The full paths of the files that should be unlocked</param>
        public async Task UnlockAsync(params string[] filePaths)
        {
            List<FileLocker> fileLockers = await FindLockingProcessesAsync(filePaths);
            foreach (FileLocker f in fileLockers)
            {
                await UnlockAsync(f);
            }
        }

        #endregion ProcessLocks

        #region HandleLocks

        /// <summary>
        /// Retrieve the <see cref="FileLockerEx"/> object that contains a List of handles that are locking a file.
        /// </summary>
        /// <param name="filePath">The full or partial path of a file or directory.</param>
        /// <param name="filter">By default, only handles whose object's Type is confirmed to "File" are returned. Optionally, handles for data pipes, printers, and other Types can be included, in addition to handles whose object Type could not be identified for some reason.</param>
        /// <returns>The <see cref="FileLockerEx"/> object that contains the <paramref name="filePath"/> and a list of handles matching the <paramref name="filter"/>.</returns>
        public FileLockerEx FindLockingHandles(string filePath, HandlesFilter filter, out WarningException? warningException)
        {
            warningException = null;
            try
            {
                return new(filePath, filter, RethrowExceptions, out warningException);
            }
            catch (UnauthorizedAccessException) when (!RethrowExceptions)
            { return new(); }
        }

        /// <summary>
        /// Retrieve the List of <see cref="FileLockerEx"/> objects for one or multiple files and/or directories
        /// </summary>
        /// <param name="filter">By default, only handles whose object's Type is confirmed to "File" are returned. Optionally, handles for data pipes, printers, and other Types can be included, in addition to handles whose object Type could not be identified for some reason.</param>
        /// <returns>The List of <see cref="FileLockerEx"/> objects that contains a List of handles that are locking one or multiple files and/or directories</returns>
        public List<FileLockerEx> FindLockingHandles(HandlesFilter filter, List<WarningException> warnings, params string[] filePaths)
        {
            List<FileLockerEx> fileLockers = new();
            warnings = new();

            if (filePaths.Length == 1)
            {
                fileLockers.Add(FindLockingHandles(filePaths[0], filter, out WarningException? warningException));
                if (warningException != null) warnings.Add(warningException);
            }
            else
            {
                foreach (string filePath in filePaths)
                {
                    fileLockers.Add(FindLockingHandles(filePath, filter, out WarningException? warningException));
                    if (warningException != null) warnings.Add(warningException);
                }
            }
            return fileLockers;
        }

        /// <summary>
        /// Asynchronously retrieve the <see cref="FileLockerEx"/> object that contains a List of handles that are locking a file or directory
        /// </summary>
        /// <param name="filePath">The full or partial path of a file</param>
        /// <param name="filter">By default, only handles whose object's Type is confirmed to "File" are returned. Optionally, handles for data pipes, printers, and other Types can be included, in addition to handles whose object Type could not be identified for some reason.</param>
        /// <returns>The <see cref="FileLockerEx"/> object that contains a List of handles that are locking a file or directory</returns>
        public static async Task<FileLockerEx> FindLockingHandlesAsync(string filePath, HandlesFilter filter = HandlesFilter.FilesOnly)
        {
            FileLockerEx fileLocker = new();

            await Task.Run(() =>
            {
                fileLocker = new(filePath,
                    NativeMethods.FindLockingHandles(filePath, filter));
            });

            return fileLocker;
        }

        /// <summary>
        ///  Asynchronously retrieve the List of <see cref="FileLockerEx"/> objects for one or multiple files and/or directories
        /// </summary>
        /// <param name="filePaths">The full or partial paths of files and/or directories </param>
        /// <returns>The List of <see cref="FileLockerEx"/> objects that contain the handles that are locking a file or directory</returns>
        public static async Task<List<FileLockerEx>> FindLockingHandlesAsync(HandlesFilter filter = HandlesFilter.FilesOnly, params string[] filePaths)
        {
            List<FileLockerEx> fileLockers = new();

            await Task.Run(() =>
            {
                foreach (string filePath in filePaths)
                {
                    fileLockers.Add(new FileLockerEx(filePath,
                        NativeMethods.FindLockingHandles(filePath, filter)));
                }
            });

            return fileLockers;
        }

        /// <summary>
        /// Unlock a File or Directory by leveraging undocumented kernel functions to make all processes release their handles of the file
        /// Release the system handle.
        /// ! WARNING !
        /// ! If a handle or a duplicate of a handle is in use by a driver or other kernel-level software, a function that accesses the now-invalid handle can cause a stopcode (AKA Blue Screen Of Death).<br/>
        /// ! Be very wary of potentially destabilizing your or your end-user's system!<br/>
        /// ! Even more so if you used the <see cref="HandlesFilter.IncludeFailedTypeQuery"/> or <see cref="HandlesFilter.IncludeNonFiles"/> filter flags
        /// </summary>
        /// <param name="fileLocker">The <see cref="FileLockerEx"/> that contains the List of handles that should be released</param>
        public void UnlockEx(FileLockerEx fileLocker)
        {
            foreach (SafeFileHandleEx h in fileLocker.Lockers)
            {
                if (h.IsClosed && h.IsInvalid) continue;
                try
                {
                    h.CloseSourceHandle();
                }
                catch (Exception) when (!RethrowExceptions) { }
            }
        }

        /// <summary>
        /// Unlock one or more files or directories by directing each handle's owner process to release the handle
        /// ! WARNING !
        /// ! If a handle or a duplicate of a handle is in use by a driver or other kernel-level software, a function that accesses the now-invalid handle can cause a stopcode (AKA Blue Screen Of Death).<br/>
        /// ! Be very wary of potentially destabilizing your or your end-user's system!<br/>
        /// ! Even more so if you used the <see cref="HandlesFilter.IncludeFailedTypeQuery"/> or <see cref="HandlesFilter.IncludeNonFiles"/> filter flags
        /// </summary>
        /// <param name="fileLockers">The <see cref="FileLockerEx"/> objects that contain the List of handles that are locking a file or directory</param>
        public void UnlockEx(params FileLockerEx[] fileLockers)
        {
            foreach (FileLockerEx fileLocker in fileLockers)
            {
                UnlockEx(fileLocker);
            }
        }

        /// <summary>
        /// Unlock a File or Directory asynchronously by directing each handle's owner process to release the handle
        /// </summary>
        /// <param name="fileLocker">The <see cref="FileLockerEx"/> that contains the List of handles that should be released</param>
        public async Task UnlockExAsync(FileLockerEx fileLocker)
        {
            await Task.Run(() =>
            {
                foreach (SafeFileHandleEx h in fileLocker.Lockers)
                {
                    if (h.IsClosed && h.IsInvalid) continue;
                    try
                    {
                        h.CloseSourceHandle();
                    }
                    catch (Exception) when (!RethrowExceptions) { }
                }
            });
        }

        /// <summary>
        /// Unlock one or more files/directories asynchronously by directing each handle's owner process to release the relevant handles
        /// </summary>
        /// <param name="fileLockers">The <see cref="FileLockerEx"/> objects that contain the List of handles that are locking a file/directory</param>
        public async Task UnlockExAsync(params FileLockerEx[] fileLockers)
        {
            await Task.Run(() =>
            {
                foreach (FileLockerEx fileLocker in fileLockers)
                {
                    foreach (SafeFileHandleEx h in fileLocker.Lockers)
                    {
                        if (h.IsClosed && h.IsInvalid) continue;
                        try
                        {
                            h.CloseSourceHandle();
                        }
                        catch (Exception) when (!RethrowExceptions) { }
                    }
                }
            });
        }

        /// <summary>
        /// Unlock a file/directory without retrieving the List of FileLockerEx objects
        /// </summary>
        /// <param name="filePath">The path of the file/directory that should be unlocked</param>
        public void UnlockEx(string filePath)
        {
            FileLockerEx fileLocker = FindLockingHandles(filePath, HandlesFilter.FilesOnly, out _);
            UnlockEx(fileLocker);
        }

        /// <summary>
        /// Unlock a file/directory without retrieving the List of FileLockerEx objects asynchronously
        /// </summary>
        /// <param name="filePath">The path of the file/directory that should be unlocked</param>
        public async Task UnlockExAsync(string filePath)
        {
            FileLockerEx locker = await FindLockingHandlesAsync(filePath);
            await UnlockExAsync(locker);
        }

        /// <summary>
        /// Unlock one or more files/directories without retrieving the List of FileLockerEx objects
        /// </summary>
        /// <param name="filePaths">The full or partial paths of the files/directories that should be unlocked</param>
        public void UnlockEx(params string[] filePaths)
        {
            foreach (FileLocker fileLocker in FindLockingProcesses(filePaths))
            {
                Unlock(fileLocker);
            }
        }

        /// <summary>
        /// Unlock one or more files/directories without retrieving the List of FileLockerEx objects asynchronously
        /// </summary>
        /// <param name="filePaths">The full or partial paths of the files/directories that should be unlocked</param>
        public async Task UnlockExAsync(params string[] filePaths)
        {
            List<FileLockerEx> fileLockers = await FindLockingHandlesAsync(HandlesFilter.FilesOnly, filePaths);
            foreach (FileLockerEx f in fileLockers)
            {
                await UnlockExAsync(f);
            }
        }

        #endregion HandleLocks
    }
}
