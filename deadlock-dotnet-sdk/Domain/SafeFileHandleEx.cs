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
    private (bool? v, Exception? ex) isDirectory;
    private (bool? v, Exception? ex) isFileHandle;
    private (bool? v, Exception? ex) isFilePathRemote;
    private (string? v, Exception? ex) fileFullPath;
    private (FileType? v, Exception? ex) fileHandleType;
    private (string? v, Exception? ex) fileName;
    private (string? v, Exception? ex) fileNameInfo;
    //private (FileShare? v, Exception? ex) fileShareAccess; // see property

    // TODO: there's gotta be a better way to cast a base class to an inheriting class
    internal SafeFileHandleEx(SafeHandleEx safeHandleEx) : this(safeHandleEx.SysHandleEx)
    { }

    /// <summary>Initialize</summary>
    /// <param name="sysHandleEx"></param>
    internal SafeFileHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx) : base(sysHandleEx: sysHandleEx)
    {
        if (IsClosed)
        {
            ExceptionLog.Add(new NullReferenceException("This handle was closed before it was passed to this SafeFileHandleEx constructor."));
            return;
        }

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

    #region Properties

    public (bool? v, Exception? ex) IsDirectory
    {
        get
        {
            if (isDirectory is (null, null))
            {
                const string errUnableMsg = "Unable to query " + nameof(IsDirectory) + "; ";
                const string errFailedMsg = "Failed to query " + nameof(IsDirectory) + "; ";
                if (IsClosed)
                    return isDirectory = (null, new NullReferenceException(errUnableMsg + errHandleClosedMsgSuffix));
                FILE_ATTRIBUTE_TAG_INFO attr = default;
                bool success;
                unsafe
                {
                    success = GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileAttributeTagInfo, &attr, (uint)Marshal.SizeOf(attr));
                }

                if (success)
                    return isDirectory = ((attr.FileAttributes & (uint)FileAttributes.Directory) != 0, null);

                Win32ErrorCode err = (Win32ErrorCode)Marshal.GetLastPInvokeError();
                return isDirectory = (null, new Win32Exception(err, errFailedMsg + err.GetMessage()));
            }
            else
            {
                return isDirectory;
            }
        }
    }

    public (bool? v, Exception? ex) IsFileHandle
    {
        get
        {
            if (isFileHandle is (null, null))
            {
                const string errUnableMsg = "Unable to query " + nameof(IsFileHandle) + "; ";
                if (IsClosed)
                    return isFileHandle = (null, new NullReferenceException(errUnableMsg + errHandleClosedMsgSuffix));
                return HandleObjectType.v == "File"
                    ? (isFileHandle = (true, null))
                    : (isFileHandle = (null, new Exception("Failed to determine if this handle's object is a file/directory; Failed to query the object's type.", HandleObjectType.ex)));
            }
            else
            {
                return isFileHandle;
            }
        }
    }

    /// <summary>
    /// TRUE if the file object's path is a network path i.e. SMB2 network share. FALSE if the file was opened via a local disk path.
    /// -OR-
    /// Exception encountered because GetFileInformationByHandleEx failed
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         GetFileInformationByHandleEx is another poorly documented win32
    ///         function due to the variety of parameters and conditional return
    ///         values. When <see cref="FILE_INFO_BY_HANDLE_CLASS.FileRemoteProtocolInfo"/>
    ///         is passed to the function, it will try to write a
    ///         <see cref="FILE_REMOTE_PROTOCOL_INFO"/> to the supplied buffer.
    ///         If the file handle's path is not remote, then the function
    ///         returns <see cref="Win32ErrorCode.ERROR_INVALID_PARAMETER"/>.
    ///     </para>
    ///     <para>
    ///         For the particulars of GetFileInformationByHandleEx, see...<br/>
    ///         * <seealso href="https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex">GetFileInformationByHandleEx function (winbase.h) | Microsoft Learn</seealso><br/>
    ///         * <seealso href="https://stackoverflow.com/a/70466900/14894786">c++ - Detect if file is open locally or over share - Stack Overflow</seealso><br/>
    ///         * <seealso href="https://web.archive.org/web/20190123140707/https://blogs.msdn.microsoft.com/winsdk/2015/06/04/filesystemwatcher-fencingpart-1/">FileSystemWatcher Fencing(Part 1) – Windows SDK Support Team Blog</seealso><br/>
    ///     </para>
    /// </remarks>
    public (bool? v, Exception? ex) IsFilePathRemote
    {
        get
        {
            if (isFilePathRemote is (null, null))
            {
                const string errUnableMsg = "Unable to query " + nameof(IsFilePathRemote) + "; ";
                const string errFailedMsg = "Failed to query " + nameof(IsFilePathRemote) + "; ";
                if (IsClosed)
                    return isFilePathRemote = (null, new NullReferenceException(errUnableMsg + errHandleClosedMsgSuffix));

                Win32ErrorCode err;
                FILE_REMOTE_PROTOCOL_INFO info;
                unsafe
                {
                    return GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileRemoteProtocolInfo, &info, (uint)Marshal.SizeOf(info))
                        ? (isFilePathRemote = (true, null))
                        : (err = (Win32ErrorCode)Marshal.GetLastPInvokeError()) is Win32ErrorCode.ERROR_INVALID_PARAMETER
                            ? (isFilePathRemote = (false, null))
                            : (isFilePathRemote = (null, new Win32Exception(err, errFailedMsg + err.GetMessage())));
                }
            }
            else
            {
                return isFilePathRemote;
            }
        }
    }

    /// <summary>
    /// Try to get the absolute path of the file. Traverses filesystem links (e.g. symbolic, junction) to get the 'real' path.
    /// </summary>
    /// <returns>If successful, returns a path string formatted as 'X:\dir\file.ext' or 'X:\dir'</returns>
    /// <remarks>GetFinalPathNameByHandle will sometimes hang when querying the Name of a Pipe.</remarks>
    public unsafe (string? v, Exception? ex) FileFullPath
    {
        get
        {
            if (fileFullPath is (null, null))
            {
                const string errUnableMsg = "Unable to query " + nameof(FileFullPath) + "; ";
                const string errFailedMsg = "Failed to query " + nameof(FileFullPath) + "; ";
                if (IsClosed)
                    return fileFullPath = (null, new NullReferenceException(errUnableMsg + errHandleClosedMsgSuffix));
                try
                {
                    if (ProcessInfo.ProcessProtection.v is null)
                        return fileFullPath = (null, new InvalidOperationException(errUnableMsg + "Failed to query the process's protection.", ProcessInfo.ProcessProtection.ex));
                    if (ProcessInfo.ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected)
                        return fileFullPath = (null, new UnauthorizedAccessException(errUnableMsg + "The process is protected."));
                    if (HandleObjectType.v is null)
                        return fileFullPath = (null, new InvalidOperationException(errUnableMsg + "Failed to query handle object type.", HandleObjectType.ex));
                    if (IsFileHandle.v is false)
                        return fileFullPath = (null, new ArgumentException(errUnableMsg + "The handle's object is not a File.", nameof(IsFileHandle)));
                    if (FileHandleType.v is not FileType.Disk)
                        return fileFullPath = (null, new ArgumentException(errUnableMsg + "The File object is not a Disk-type File.", nameof(FileHandleType)));

                    uint bufLength = (uint)short.MaxValue;
                    using PWSTR buffer = new((char*)Marshal.AllocHGlobal((int)bufLength));
                    uint length = 0;
                    const uint LengthIndicatesError = 0;

                    // Try without duplicating. If it fails, try duplicating the handle.
                    Stopwatch sw = Stopwatch.StartNew();
                    try
                    {
                        GETFINALPATHNAMEBYHANDLE_FLAGS flags = IsFilePathRemote.v is true ? GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_OPENED : GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_NORMALIZED;
                        Win32ErrorCode errorCode = Win32ErrorCode.ERROR_SUCCESS;
                        length = GetFinalPathNameByHandle(handle, buffer, bufLength, flags);

                        if (length is not LengthIndicatesError)
                        {
                            if (length <= bufLength)
                            {
                                return fileFullPath = (buffer.ToString(), null);
                            }
                            else if (length > bufLength)
                            {
                                using PWSTR newBuffer = new((char*)Marshal.AllocHGlobal((int)length));
                                if ((length = GetFinalPathNameByHandle(handle, newBuffer, length, flags)) is not LengthIndicatesError)
                                    return fileFullPath = (newBuffer.ToString(), null);
                            }
                        }
                        else
                        {
                            errorCode = (Win32ErrorCode)Marshal.GetLastPInvokeError();

                            Trace.TraceError(errorCode.GetMessage());

                            return fileFullPath = (null, errorCode switch
                            {
                                // Removable storage, deleted item, network shares, et cetera
                                Win32ErrorCode.ERROR_PATH_NOT_FOUND => new FileNotFoundException(errFailedMsg + $"The path '{buffer}' was not found when querying a file handle.", fileName: buffer.ToString(), new Win32Exception(errorCode)),
                                // unlikely, but possible if system has little free memory
                                Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException(errFailedMsg + "Insufficient memory to complete the operation.", new Win32Exception(errorCode)),
                                // possible only if FILE_NAME_NORMALIZED (0) is invalid
                                Win32ErrorCode.ERROR_INVALID_PARAMETER => new ArgumentException(errFailedMsg + "Invalid flags were specified for dwFlags.", new Win32Exception(errorCode)),
                                _ => new Exception($"{errFailedMsg}An undocumented error ({errorCode}) was returned when querying a file handle for its path.", new Win32Exception(errorCode))
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        return fileFullPath = (null, ex);
                    }
                    finally
                    {
                        sw.Stop();
                        Console.WriteLine($"(handle 0x{handle:X}) TryGetFinalPath time: {sw.Elapsed}");
                    }

                    /// Return the normalized drive name. This is the default.
                    using SafeProcessHandle processHandle = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, false, ProcessId);
                    if (processHandle is null || processHandle?.IsInvalid == true)
                        throw new Win32Exception();

                    if (!DuplicateHandle(processHandle, this, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS))
                        throw new Win32Exception();

                    length = GetFinalPathNameByHandle(dupHandle, buffer, bufLength, GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_NORMALIZED);

                    if (length != 0)
                    {
                        if (length <= bufLength)
                            return fileFullPath = (buffer.ToString(), null);

                        {
                            // buffer was too small. Reallocate buffer with size matched 'length' and try again
                            using PWSTR newBuffer = new((char*)Marshal.AllocHGlobal((int)length));
                            bufLength = GetFinalPathNameByHandle(dupHandle, buffer, bufLength, GETFINALPATHNAMEBYHANDLE_FLAGS.FILE_NAME_NORMALIZED);
                            return fileFullPath = (newBuffer.ToString(), null);
                        }
                    }
                    else
                    {
                        Win32ErrorCode error = (Win32ErrorCode)Marshal.GetLastWin32Error();
                        Trace.TraceError(error.GetMessage());

                        return (null, error switch
                        {
                            // Removable storage, deleted item, network shares, et cetera
                            Win32ErrorCode.ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{buffer}' was not found when querying a file handle.", fileName: buffer.ToString(), new Win32Exception(error)),
                            // unlikely, but possible if system has little free memory
                            Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation.", new Win32Exception(error)),
                            // possible only if FILE_NAME_NORMALIZED (0) is invalid
                            Win32ErrorCode.ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags.", new Win32Exception(error)),
                            _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path.", new Win32Exception(error))
                        });
                    }
                }
                catch (Exception ex)
                {
                    return fileFullPath = (null, ex);
                }
            }
            else
            {
                return fileFullPath;
            }
        }
    }

    /// <summary>
    /// If the handle object's Type is "File", the type of the File object<br/>
    /// -OR-<br/>
    /// An exception if the P/Invoke operation failed or the object's Type is not "File".
    /// </summary>
    public (FileType? v, Exception? ex) FileHandleType
    {
        get
        {
            if (fileHandleType is (null, null))
            {
                const string errUnableMsg = "Unable to query " + nameof(FileHandleType) + "; ";
                const string errFailedMsg = "Failed to query " + nameof(FileHandleType) + "; ";
                if (IsClosed)
                    return fileHandleType = (null, new NullReferenceException(errUnableMsg + errHandleClosedMsgSuffix));
                if (ProcessInfo.ProcessProtection.ex is not null)
                    return fileHandleType = (null, new NullReferenceException(errUnableMsg + "Failed to query the process's protection level."));
                if (ProcessInfo.ProcessProtection.ex is not null)
                    return fileHandleType = (null, new UnauthorizedAccessException(errUnableMsg + "The process's protection prohibits this operation."));
                if (IsFileHandle.v is not true)
                    return fileHandleType = (null, new InvalidOperationException(errUnableMsg + "This operation is only valid on File handles."));

                FileType type = (FileType)GetFileType(handle);
                if (type is FileType.Unknown)
                {
                    Win32ErrorCode err = (Win32ErrorCode)Marshal.GetLastPInvokeError();
                    if (err is not Win32ErrorCode.ERROR_SUCCESS)
                        return fileHandleType = (null, new Win32Exception(err, errFailedMsg + err.GetMessage()));
                }

                return fileHandleType = (type, null);
            }
            else
            {
                return fileHandleType;
            }
        }
    }

    public (string? v, Exception? ex) FileName
    {
        get
        {
            if (fileName is (null, null))
            {
                const string errUnableMsg = "Unable to query " + nameof(FileName) + "; ";
                const string errFailedMsg = "Failed to query " + nameof(FileName) + "; ";
                if (IsClosed)
                    return objectName = (null, new NullReferenceException(errUnableMsg + errHandleClosedMsgSuffix));
                if (FileFullPath.v is not null)
                {
                    getFileOrDirectoryName(FileFullPath.v);
                    return fileName;
                }
                else if (FileNameInfo.v is not null)
                {
                    getFileOrDirectoryName(FileNameInfo.v);
                    return fileName;
                }
                else if (ObjectName.v is not null)
                {
                    getFileOrDirectoryName(ObjectName.v);
                    return fileName;
                }
                else
                {
                    return fileName = (null, new InvalidOperationException(errUnableMsg + "This operation requires FileFullPath, FileNameInfo, or ObjectName."));
                }

                void getFileOrDirectoryName(string path)
                {
                    string? tmp = Path.GetFileName(path);
                    if (tmp.Length is 0)
                    {
                        fileName = (tmp = Path.GetDirectoryName(path)) is null
                            ? (null, new InvalidOperationException(errFailedMsg + $"'{path}' could not be processed for a file or directory name."))
                            : (tmp, null);
                    }
                    else
                    {
                        fileName = (tmp, null);
                    }
                }
            }
            else
            {
                return fileName;
            }
        }
    }

    public unsafe (string? v, Exception? ex) FileNameInfo
    {
        get
        {
            if (fileNameInfo is (null, null))
            {
                const string errUnableMsg = "Unable to query " + nameof(FileNameInfo) + "; ";
                const string errFailedMsg = "Failed to query " + nameof(FileNameInfo) + "; ";
                if (IsClosed)
                    return objectName = (null, new NullReferenceException(errUnableMsg + errHandleClosedMsgSuffix));
                if (ProcessInfo.ProcessProtection.ex is not null)
                    return fileNameInfo = (null, new NullReferenceException(errUnableMsg + "Failed to query the process's protection level.", ProcessInfo.ProcessProtection.ex));
                if (ProcessInfo.ProcessProtection.v?.Type is not PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeNone)
                    return fileNameInfo = (null, new UnauthorizedAccessException(errUnableMsg + "The process's protection prohibits querying a file handle's FILE_NAME_INFO."));
                if (FileHandleType.v is not FileType.Disk)
                    return fileNameInfo = (null, new InvalidOperationException(errUnableMsg + "FileNameInfo can only be queried for disk-type file handles."));

                /** Get fni.FileNameLength */
                FILE_NAME_INFO fni = default;
                _ = GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileNameInfo, &fni, (uint)Marshal.SizeOf(fni));

                /** Get FileNameInfo */
                int bufferLength = (int)(fni.FileNameLength + Marshal.SizeOf(fni));
                using SafeBuffer<FILE_NAME_INFO> safeBuffer = new(numBytes: (nuint)bufferLength);

                if (!GetFileInformationByHandleEx(this, FILE_INFO_BY_HANDLE_CLASS.FileNameInfo, (FILE_NAME_INFO*)safeBuffer.DangerousGetHandle(), (uint)bufferLength))
                    return fileNameInfo = (null, new Exception(errFailedMsg + "GetFileInformationByHandleEx encountered an error.", new Win32Exception()));

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
                return fileNameInfo;
            }
        }
    }

    public Kernel32.HandleFlags HandleAttributes => SysHandleEx.HandleAttributes;

    /// <summary>
    /// Inaccessible by user code; Only available to kernel-mode drivers; <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocheckshareaccessex"/>
    /// </summary>
    //public unsafe (FileShare? v, Exception? ex) FileShareAccess { get { if (fileShareAccess is (null, null)) { _ } else { return fileShareAccess; } } }

    #endregion Properties

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

    public override string ToString() => ToString(false, false);

    /// <summary>
    /// Get the string representation of this SafeFileHandleEx object.
    /// </summary>
    /// <param name="initProps">If TRUE, get values from Properties. If FALSE, get values from Properties' backing fields.</param>
    /// <returns>The string representation of this SafeFileHandleEx object.</returns>
    public string ToString(bool initProps, bool initProcessInfo)
    {
        try
        {
            string[] exLog = ExceptionLog.ConvertAll(ex => ex.ToString()).ToArray();
            for (int i = 0; i < exLog.Length; i++)
            {
                exLog[i] = $" {exLog[i]}".Replace("\n", "\n    ") + "\r\n";
            }

            return @$"{nameof(SafeFileHandleEx)} hash:{GetHashCode()}
        {nameof(CreatorBackTraceIndex)}             : {CreatorBackTraceIndex}
        {nameof(FileFullPath)}                      : {(initProps ? (FileFullPath.v ?? FileFullPath.ex?.ToString()) : (fileFullPath.v ?? fileFullPath.ex?.ToString()))}
        {nameof(FileHandleType)}                    : {(initProps ? (FileHandleType.v?.ToString() ?? FileFullPath.ex?.ToString()) : (fileHandleType.v?.ToString() ?? fileHandleType.ex?.ToString()))}
        {nameof(FileName)}                          : {(initProps ? (FileName.v ?? FileName.ex?.ToString()) : (fileName.v ?? fileName.ex?.ToString()))}
        {nameof(GrantedAccess)}                     : {SysHandleEx.GrantedAccessString}
        {nameof(HandleObjectType)}                  : {(initProps ? (HandleObjectType.v ?? HandleObjectType.ex?.ToString()) : (handleObjectType.v ?? handleObjectType.ex?.ToString()))}
        {nameof(HandleValue)}                       : {HandleValue} (0x{HandleValue:X})
        {nameof(IsClosed)}                          : {IsClosed}
        {nameof(IsDirectory)}                       : {(initProps ? (IsDirectory.v?.ToString() ?? IsDirectory.ex?.ToString()) : (isDirectory.v?.ToString() ?? isDirectory.ex?.ToString()))}
        {nameof(IsFileHandle)}                      : {(initProps ? (IsFileHandle.v?.ToString() ?? IsFileHandle.ex?.ToString()) : (isFileHandle.v?.ToString() ?? isFileHandle.ex?.ToString()))}
        {nameof(IsInvalid)}                         : {IsInvalid}
        {nameof(ObjectAddress)}                     : {ObjectAddress} (0x{ObjectAddress:X})
        {nameof(ObjectName)}                        : {(initProps ? (ObjectName.v ?? ObjectName.ex?.ToString()) : (objectName.v ?? objectName.ex?.ToString()))}
        {nameof(ProcessId)}                         : {ProcessId}
        {nameof(ProcessInfo.ParentId)}              : {(initProcessInfo ? (ProcessInfo.ParentId.v?.ToString() ?? ProcessInfo.ParentId.ex?.ToString()) : (processInfo?.ParentId.v?.ToString() ?? processInfo?.ParentId.ex?.ToString() ?? string.Empty))}
        {nameof(ProcessInfo.ProcessCommandLine)}    : {(initProcessInfo ? (ProcessInfo.ProcessCommandLine.v ?? ProcessInfo.ProcessCommandLine.ex?.ToString()) : (processInfo?.ProcessCommandLine.v ?? processInfo?.ProcessCommandLine.ex?.ToString() ?? string.Empty))}
        {nameof(ProcessInfo.ProcessMainModulePath)} : {(initProcessInfo ? (ProcessInfo.ProcessMainModulePath.v ?? ProcessInfo.ProcessMainModulePath.ex?.ToString()) : (processInfo?.ProcessMainModulePath.v ?? processInfo?.ProcessMainModulePath.ex?.ToString() ?? string.Empty))}
        {nameof(ProcessInfo.ProcessName)}           : {(initProcessInfo ? (ProcessInfo.ProcessName.v ?? ProcessInfo.ProcessName.ex?.ToString()) : (processInfo?.ProcessName.v ?? processInfo?.ProcessName.ex?.ToString() ?? string.Empty))}
        {nameof(ProcessInfo.ProcessProtection)}     : {(initProcessInfo ? (ProcessInfo.ProcessProtection.v?.ToString() ?? ProcessInfo.ProcessProtection.ex?.ToString()) : (processInfo?.ProcessProtection.v?.ToString() ?? processInfo?.ProcessProtection.ex?.ToString() ?? string.Empty))}
        {nameof(ExceptionLog)}                      : ...
        " + string.Concat(exLog);
        }
        catch (Exception ex)
        {
            return $"Error while evaluating properties for SafeFileHandleEx.ToString(): {ex}";
        }
    }
}
