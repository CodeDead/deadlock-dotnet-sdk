﻿using System.Diagnostics;

namespace deadlock_dotnet_sdk.Domain
{
    public class FileLocker
    {
        #region Properties

        /// <summary>
        /// Get the path of the file that is locked
        /// </summary>
        public string Path { get; }

        /// <summary>
        /// Get the List of Process objects that are locking the file
        /// </summary>
        public List<Process> Lockers { get; }

        #endregion

        /// <summary>
        /// Initialize a new FileLocker
        /// </summary>
        public FileLocker()
        {
            Path = "";
            Lockers = new List<Process>();
        }

        /// <summary>
        /// Initialize a new FileLocker
        /// </summary>
        /// <param name="path">The path of the file</param>
        /// <param name="lockers">The List of Process objects that are locking the file</param>
        public FileLocker(string path, List<Process> lockers)
        {
            Path = path;
            Lockers = lockers;
        }
    }
}
