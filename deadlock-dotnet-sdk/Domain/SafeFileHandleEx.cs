using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Storage.FileSystem;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;

// Re: StructLayout
// "C#, Visual Basic, and C++ compilers apply the Sequential layout value to structures by default."
// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.structlayoutattribute?view=net-6.0#remarks

// new Win32Exception() is defined as
// public Win32Exception() : this(Marshal.GetLastPInvokeError())
// {
// }

namespace deadlock_dotnet_sdk.Domain;
/// <summary>
/// A SafeFileHandle-like wrapper for the undocumented Windows type "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"
/// </summary>
public class SafeFileHandleEx : SafeHandleEx
{
    private (bool? v, Exception? ex) isFileHandle;
    private (FileType? v, Exception? ex) fileHandleType;
    private (string? v, Exception? ex) fileNameInfo;
    private (string? v, Exception? ex) fileFullPath;
    private (string? v, Exception? ex) fileName;
    private (bool? v, Exception? ex) isDirectory;

    // TODO: there's gotta be a better way to cast a base class to an implementing class
    internal SafeFileHandleEx(SafeHandleEx safeHandleEx) : this(safeHandleEx.SysHandleEx)
    { }

    /// <summary>Initialize</summary>
    /// <param name="sysHandleEx"></param>
    internal SafeFileHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx) : base(sysHandleEx: sysHandleEx)
    {
        if (IsFileHandle.v is true)
        {
            try
            {
                if (ProcessInfo.ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected)
                {
                    if (ProcessInfo.ProcessName.v is "smss")
                        ExceptionLog.Add(new UnauthorizedAccessException($"The Handle's Name is inaccessible because the handle is owned by Windows Session Manager SubSystem ({ProcessInfo.ProcessName}, PID {ProcessId})"));
                    else
                        ExceptionLog.Add(new UnauthorizedAccessException($"The Handle's Name is inaccessible because the handle is owned by {ProcessInfo.ProcessName} (PID {ProcessId})"));
                }
            }
            catch (Exception e)
            {
                ExceptionLog.Add(e);
            }
        }
        else
        {
            ExceptionLog.Add(new InvalidCastException("Cannot cast non-file handle to file handle!"));
        }
    }

    public (bool? v, Exception? ex) IsFileHandle => isFileHandle == default
                ? HandleObjectType.v == "File"
                    ? (isFileHandle = (true, null))
                    : (isFileHandle = (null, new Exception("Failed to determine if this handle's object is a file/directory; Failed to query the object's type.", HandleObjectType.ex)))
                : isFileHandle;

    public (FileType? v, Exception? ex) FileHandleType
    {
        get
        {
            if (fileHandleType == default)
            {
                if (IsFileHandle.v is not true)
                    return (null, new InvalidOperationException("Unable to query File handle type; This operation is only valid on File handles."));

                FileType type = (FileType)GetFileType(handle);
                var err = new Win32Exception();
                return err.ErrorCode is 0 /* success */
                    ? fileHandleType = (type, null)
                    : fileHandleType = (null, err);
            }
            else
            {
                return fileHandleType;
            }
        }
    }

    public unsafe (string? v, Exception? ex) FileNameInfo
    {
        get
        {
            if (fileNameInfo == default)
            {
                if (FileHandleType.v is not FileType.Disk)
                    return (null, new InvalidOperationException("FileNameInfo can only be queried for disk-type file handles."));
                //TODO: check if process protection inhibits function
                //if (ProcessProtection.ex is not null)
                //if (ProcessProtection.v?.Value.Type )

                /* Get fni.FileNameLength */
                FILE_NAME_INFO fni = default;
                int fniSize = Marshal.SizeOf(fni);
                int bufferLength = default;

                using CancellationTokenSource cancellationTokenSource = new(50);
                Task<FILE_NAME_INFO> taskGetInfo = new(() =>
                {
                    FILE_NAME_INFO tmp = default;
                    _ = GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileNameInfo, &tmp, (uint)Marshal.SizeOf(fni));
                    return tmp;
                }, cancellationTokenSource.Token);

                const int taskTimedOut = -1;
                try
                {
                    if (Task.WaitAny(new Task[] { taskGetInfo }, 50) is taskTimedOut)
                    {
                        return (null, new TimeoutException("GetFileInformationByHandleEx did not respond within 50ms."));
                    }
                    else
                    {
                        bufferLength = (int)(taskGetInfo.Result.FileNameLength + fniSize);
                    }
                }
                catch (AggregateException ae)
                {
                    foreach (Exception e in ae.InnerExceptions)
                    {
                        if (e is TaskCanceledException)
                            return (null, e);
                    }
                }

                /* Get FileNameInfo */
                FILE_NAME_INFO* buffer = (FILE_NAME_INFO*)Marshal.AllocHGlobal(bufferLength);
                using SafeBuffer<FILE_NAME_INFO> safeBuffer = new(numBytes: (nuint)bufferLength);

                if (GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileNameInfo, buffer, (uint)bufferLength))
                {
                    UNICODE_STRING str = new()
                    {
                        Buffer = new PWSTR((char*)safeBuffer.DangerousGetHandle()),
                        Length = (ushort)fni.FileNameLength,
                        MaximumLength = (ushort)bufferLength
                    };

                    /* The string conversion copies the data to a new string in the managed heap before freeing safeBuffer and leaving this context. */
                    return fileNameInfo = ((string)str, null);
                }
                else
                {
                    return (null, new Exception("Failed to query FileNameInfo; GetFileInformationByHandleEx encountered an error.", new Win32Exception()));
                }
            }
            else
            {
                return fileNameInfo;
            }
        }
    }

    public (string? v, Exception? ex) FileFullPath => fileFullPath == default ? (fileFullPath = TryGetFinalPath()) : fileFullPath;

    // TODO: leverage GetFileInformationByHandleEx
    public (string? v, Exception? ex) FileName
    {
        get
        {
            if (fileName == default)
            {
                if (FileFullPath.v is not null)
                {
                    return fileName = (Path.GetFileName(FileFullPath.v), null);
                }
                else
                {
                    return fileName = (null, new InvalidOperationException("Unable to query FileName; This operation requires FileFullPath."));
                }
            }
            else
            {
                return fileName;
            }
        }
    }

    public (bool? v, Exception? ex) IsDirectory
    {
        get
        {
            if (isDirectory == default)
            {
                if (FileFullPath != default && FileFullPath.v != null) // The comparison *should* cause FileFullPath to initialize.
                {
                    try
                    {
                        return isDirectory = ((File.GetAttributes(FileFullPath.v) & FileAttributes.Directory) == FileAttributes.Directory, null);
                    }
                    catch (Exception ex)
                    {
                        return (null, ex);
                    }
                }

                return (null, new InvalidOperationException("Unable to query IsDirectory; This operation requires FileFullPath."));
            }
            else
            {
                return isDirectory;
            }
        }
    }

    public enum FileType : uint
    {
        /// <summary>Either the type of the specified file is unknown, or the function failed.</summary>
        Unknown = FILE_TYPE.FILE_TYPE_UNKNOWN,
        /// <summary>The specified file is a disk file.</summary>
        Disk = FILE_TYPE.FILE_TYPE_DISK,
        /// <summary>The specified file is a character file, typically an LPT device or a console.</summary>
        Char = FILE_TYPE.FILE_TYPE_CHAR,
        /// <summary>The specified file is a socket, a named pipe, or an anonymous pipe.</summary>
        Pipe = FILE_TYPE.FILE_TYPE_PIPE,
    }

    /// <summary>
    /// Try to get the absolute path of the file. Traverses filesystem links (e.g. symbolic, junction) to get the 'real' path.
    /// </summary>
    /// <returns>If successful, returns a path string formatted as 'X:\dir\file.ext' or 'X:\dir'</returns>
    /// <remarks>GetFinalPathNameByHandle will sometimes hang will querying the Name of a Pipe.</remarks>
    private unsafe (string? v, Exception? ex) TryGetFinalPath()
    {
        try
        {
            if (ProcessInfo.ProcessProtection.v is null)
                throw new InvalidOperationException("Unable to query disk/network path; Failed to query the process's protection:" + Environment.NewLine + ProcessInfo.ProcessProtection.ex);
            if (ProcessInfo.ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected)
                throw new UnauthorizedAccessException("Unable to query disk/network path; The process is protected.");
            if (HandleObjectType.v is null)
                throw new InvalidOperationException("Unable to query disk/network path; Failed to query handle object type." + Environment.NewLine + HandleObjectType.ex);
            if (IsFileHandle.v is false)
                throw new InvalidOperationException("Unable to query disk/network path; The handle's object is not a File.");
            if (FileHandleType.v is not FileType.Disk)
                throw new InvalidOperationException("Unable to query disk/network path; The File object is not a Disk-type File.");

            uint bufLength = (uint)short.MaxValue;
            using PWSTR buffer = new((char*)Marshal.AllocHGlobal((int)bufLength));
            uint length = 0;

            // Try without duplicating. If it fails, try duplicating the handle.
            var sw = new Stopwatch();
            sw.Start();
            try
            {
                const int timeout = 50;
                Task<uint> taskGetLength = new(() => GetFinalPathNameByHandle(handle, buffer, bufLength, FILE_NAME.FILE_NAME_NORMALIZED));
                if (Task.WhenAny(taskGetLength, Task.Delay(timeout)).Result == taskGetLength)
                    length = taskGetLength.Result;
                else
                    throw new TimeoutException($"GetFinalPathNameHandle did not complete in {timeout}ms.");

                if (length is 0)
                    throw new Win32Exception();

                if (length <= bufLength)
                {
                    return (buffer.ToString(), null);
                }
                else
                {
                    using PWSTR newBuffer = new((char*)Marshal.AllocHGlobal((int)length));
                    Task<uint> taskGetPath = new(() => GetFinalPathNameByHandle(handle, newBuffer, length, FILE_NAME.FILE_NAME_NORMALIZED));
                    if (Task.WhenAny(taskGetPath, Task.Delay(timeout)).Result == taskGetPath)
                    {
                        if (taskGetPath.Result is not 0)
                            return (newBuffer.ToString(), null);
                        else
                            throw new Win32Exception();
                    }
                    else
                    {
                        throw new TimeoutException($"GetFinalPathNameHandle did not complete in {timeout}ms.");
                    }
                }
            }
            catch (Exception ex)
            {
                _ = ex;
            }
            finally
            {
                sw.Stop();
                Console.Out.WriteLine($"(handle 0x{handle:X}) TryGetFinalPath time: {sw.Elapsed}"); // TODO: debug. Determine better timeout.
            }

            /// Return the normalized drive name. This is the default.
            using SafeProcessHandle processHandle = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, false, ProcessId);
            if (processHandle is null || processHandle?.IsInvalid == true)
                throw new Win32Exception();

            if (!DuplicateHandle(processHandle, this, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS))
                throw new Win32Exception();

            length = GetFinalPathNameByHandle(dupHandle, buffer, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);

            if (length != 0)
            {
                if (length > bufLength)
                {
                    // buffer was too small. Reallocate buffer with size matched 'length' and try again
                    using PWSTR newBuffer = new((char*)Marshal.AllocHGlobal((int)length));
                    bufLength = GetFinalPathNameByHandle(dupHandle, buffer, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);
                    return (newBuffer.ToString(), null);
                }
                else
                {
                    return (buffer.ToString(), null);
                }
            }
            else
            {
                Win32ErrorCode error = (Win32ErrorCode)Marshal.GetLastWin32Error();
                Debug.Print(error.GetMessage());

                throw error switch
                {
                    // Removable storage, deleted item, network shares, et cetera
                    Win32ErrorCode.ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{buffer}' was not found when querying a file handle.", fileName: buffer.ToString(), new Win32Exception(error)),
                    // unlikely, but possible if system has little free memory
                    Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation.", new Win32Exception(error)),
                    // possible only if FILE_NAME_NORMALIZED (0) is invalid
                    Win32ErrorCode.ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags.", new Win32Exception(error)),
                    _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path.", new Win32Exception(error))
                };
            }
        }
        catch (Exception ex)
        {
            return (null, ex);
        }
    }

    public override string ToString()
    {
        string[] exLog = ExceptionLog.ConvertAll(ex => ex.ToString()).ToArray();
        for (int i = 0; i < exLog.Length; i++)
        {
            exLog[i] = $" {exLog[i]}".Replace("\n", "\n    ") + Environment.NewLine;
        }

        return @$"{GetType().Name} hash:{GetHashCode()}
        {nameof(CreatorBackTraceIndex)}             : {CreatorBackTraceIndex}
        {nameof(FileFullPath)}                      : {FileFullPath.v ?? FileFullPath.ex?.ToString()}
        {nameof(FileHandleType)}                    : {FileHandleType.v?.ToString() ?? FileFullPath.ex?.ToString()} 
        {nameof(FileName)}                          : {FileName.v ?? FileName.ex?.ToString()}
        {nameof(GrantedAccess)}                     : {SysHandleEx.GrantedAccessString}
        {nameof(HandleObjectType)}                  : {HandleObjectType.v ?? HandleObjectType.ex?.ToString()}
        {nameof(HandleValue)}                       : {HandleValue} (0x{HandleValue:X})
        {nameof(IsClosed)}                          : {IsClosed}
        {nameof(IsDirectory)}                       : {IsDirectory.v?.ToString() ?? IsDirectory.ex?.ToString()}
        {nameof(IsFileHandle)}                      : {IsFileHandle.v?.ToString() ?? IsFileHandle.ex?.ToString()}
        {nameof(IsInvalid)}                         : {IsInvalid}
        {nameof(ObjectAddress)}                     : {ObjectAddress} (0x{ObjectAddress:X})
        {nameof(ObjectName)}                        : {ObjectName.v ?? ObjectName.ex?.ToString()}
        {nameof(ProcessId)}                         : {ProcessId}
        {nameof(ProcessInfo.ParentId)}              : {ProcessInfo.ParentId.v?.ToString() ?? ProcessInfo.ParentId.ex?.ToString() ?? string.Empty}
        {nameof(ProcessInfo.ProcessCommandLine)}    : {ProcessInfo.ProcessCommandLine.v ?? ProcessInfo.ProcessCommandLine.ex?.ToString()}
        {nameof(ProcessInfo.ProcessMainModulePath)} : {ProcessInfo.ProcessMainModulePath.v ?? ProcessInfo.ProcessMainModulePath.ex?.ToString()}
        {nameof(ProcessInfo.ProcessName)}           : {ProcessInfo.ProcessName.v ?? ProcessInfo.ProcessName.ex?.ToString()}
        {nameof(ProcessInfo.ProcessProtection)}     : {ProcessInfo.ProcessProtection.v?.ToString() ?? ProcessInfo.ProcessProtection.ex?.ToString() ?? string.Empty}
        {nameof(ExceptionLog)}                      : ...
        " + string.Concat(exLog);
    }
}
