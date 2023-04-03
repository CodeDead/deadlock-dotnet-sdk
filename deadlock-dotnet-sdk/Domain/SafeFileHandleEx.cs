using System.Data;
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
    private (TypeOfFileHandle? v, Exception? ex) fileHandleType;
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
                if (ProcessIsProtected.v == true)
                {
                    if (ProcessName.v is "smss")
                        ExceptionLog.Add(new InvalidOperationException($"The Handle's Name is inaccessible because the handle is owned by Windows Session Manager SubSystem ({ProcessName}, PID {ProcessId})"));
                    else
                        ExceptionLog.Add(new InvalidOperationException($"The Handle's Name is inaccessible because the handle is owned by {ProcessName} (PID {ProcessId})"));
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

    public (bool? v, Exception? ex) IsFileHandle => isFileHandle == default ? (isFileHandle = GetIsFileHandle()) : isFileHandle;
    public (TypeOfFileHandle? v, Exception? ex) FileHandleType
    {
        get
        {
            if (fileHandleType == default)
            {
                if (IsFileHandle.v is not true)
                    return (null, new InvalidOperationException("Unable to query File handle type; This operation is only valid on File handles."));

                try
                {
                    return fileHandleType = ((TypeOfFileHandle?)GetFileType(handle), null);
                }
                catch (Exception ex)
                {
                    return (null, ex);
                }
            }
            else
            {
                return fileHandleType;
            }
        }
    }

    public (string? v, Exception? ex) FileFullPath => fileFullPath == default ? (fileFullPath = TryGetFinalPath()) : fileFullPath;

    public (string? v, Exception? ex) FileName
    {
        get
        {
            if (fileName == default)
            {
                if (FileFullPath != default && FileFullPath.v is not null)
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

    public enum TypeOfFileHandle : uint
    {
        Unknown = FILE_TYPE.FILE_TYPE_UNKNOWN,
        Disk = FILE_TYPE.FILE_TYPE_DISK,
        Char = FILE_TYPE.FILE_TYPE_CHAR,
        Pipe = FILE_TYPE.FILE_TYPE_PIPE,
        Remote = FILE_TYPE.FILE_TYPE_REMOTE
    }

    /// <summary>
    /// Try to get the absolute path of the file. Traverses filesystem links (e.g. symbolic, junction) to get the 'real' path.
    /// </summary>
    /// <returns>If successful, returns a path string formatted as 'X:\dir\file.ext' or 'X:\dir'</returns>
    /// <exception cref="FileNotFoundException(string, string)">The path '{fullName}' was not found when querying a file handle.</exception>
    /// <exception cref="OutOfMemoryException(string)">Failed to query path from file handle. Insufficient memory to complete the operation.</exception>
    /// <exception cref="ArgumentException(string)">Failed to query path from file handle. Invalid flags were specified for dwFlags.</exception>
    private unsafe (string? v, Exception? ex) TryGetFinalPath()
    {
        if (ProcessIsProtected != default && ProcessIsProtected.v is true)
            return (null, new InvalidOperationException("Unable to query file path or pipe name; The process is protected."));
        else if (ProcessIsProtected.v is null)
            return (null, new InvalidOperationException("Unable to query file path or pipe name; Unable to query the process's protection:" + Environment.NewLine + ProcessIsProtected.ex));

        /// Return the normalized drive name. This is the default.
        using SafeProcessHandle processHandle = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, false, ProcessId);
        if (processHandle is null || processHandle?.IsInvalid == true)
            return (null, new Win32Exception());

        if (!DuplicateHandle(processHandle, this, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS))
            return (null, new Win32Exception());

        uint bufLength = (uint)short.MaxValue;
        using PWSTR buffer = new((char*)Marshal.AllocHGlobal((int)bufLength));
        uint length = GetFinalPathNameByHandle(dupHandle, buffer, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);

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
                Win32ErrorCode.ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{buffer}' was not found when querying a file handle.", fileName: buffer.ToString(), new Win32Exception(error)), // Removable storage, deleted item, network shares, et cetera
                Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation.", new Win32Exception(error)), // unlikely, but possible if system has little free memory
                Win32ErrorCode.ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags.", new Win32Exception(error)), // possible only if FILE_NAME_NORMALIZED (0) is invalid
                _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path.", new Win32Exception(error))
            };
        }
    }

    public override string ToString()
    {
        string[] exLog = ExceptionLog.Cast<string>().ToArray();
        for (int i = 0; i < exLog.Length; i++)
        {
            exLog[i] = $" {exLog[i]}".Replace("\n", "\n    ") + Environment.NewLine;
        }

        return @$"{GetType().Name} hash:{GetHashCode()}
        {nameof(CreatorBackTraceIndex)} : {CreatorBackTraceIndex}
        {nameof(FileFullPath)}          : {FileFullPath.v ?? FileFullPath.ex?.ToString()}
        {nameof(FileHandleType)}        : {FileHandleType.v?.ToString() ?? FileFullPath.ex?.ToString()} 
        {nameof(FileName)}              : {FileName.v ?? FileName.ex?.ToString()}
        {nameof(GrantedAccess)}         : {SysHandleEx.GrantedAccessString}
        {nameof(HandleObjectType)}      : {HandleObjectType.v ?? HandleObjectType.ex?.ToString()}
        {nameof(HandleValue)}           : {HandleValue} (0x{HandleValue:X})
        {nameof(IsClosed)}              : {IsClosed}
        {nameof(IsDirectory)}           : {IsDirectory.v?.ToString() ?? IsDirectory.ex?.ToString()}
        {nameof(IsFileHandle)}          : {IsFileHandle.v?.ToString() ?? IsFileHandle.ex?.ToString()}
        {nameof(IsInvalid)}             : {IsInvalid}
        {nameof(ObjectAddress)}         : {ObjectAddress} (0x{ObjectAddress:X})
        {nameof(ProcessCommandLine)}    : {ProcessCommandLine.v ?? ProcessCommandLine.ex?.ToString()}
        {nameof(ProcessId)}             : {ProcessId}
        {nameof(ProcessMainModulePath)} : {ProcessMainModulePath.v ?? ProcessMainModulePath.ex?.ToString()}
        {nameof(ProcessName)}           : {ProcessName.v ?? ProcessName.ex?.ToString()}
        {nameof(ExceptionLog)}          : ...        
        " + string.Concat(exLog);
    }
}
