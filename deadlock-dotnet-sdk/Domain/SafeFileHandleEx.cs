using System.Data;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32.Foundation;
using Windows.Win32.Storage.FileSystem;
using Windows.Win32.System.Threading;
using static deadlock_dotnet_sdk.Domain.NativeMethods;
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
    // TODO: there's gotta be a better way to cast a base class to an implementing class
    internal SafeFileHandleEx(SafeHandleEx safeHandleEx) : this(safeHandleEx.SysHandleEx)
    { }

    /// <summary>
    /// Initialize
    /// </summary>
    /// <param name="sysHandleEx"></param>
    internal SafeFileHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx) : base(sysHandleEx: sysHandleEx)
    {
        try
        {
            IsFileHandle = SysHandleEx.IsFileHandle();
        }
        catch (Exception e)
        {
            ExceptionLog.Add(e);
        }

        if (IsFileHandle == true)
        {
            try
            {
                if (ProcessId == 4)
                {
                    ExceptionLog.Add(new InvalidOperationException($"The Handle's Name is inaccessible because the handle is owned by {ProcessName} (PID {ProcessId})"));
                    return;
                }

                if (ProcessName == "smss")
                {
                    ExceptionLog.Add(new InvalidOperationException($"The Handle's Name is inaccessible because the handle is owned by Windows Session Manager SubSystem ({ProcessName}, PID {ProcessId})"));
                    return;
                }

                FileFullPath = TryGetFinalPath();
                FileName = Path.GetFileName(FileFullPath);
                IsDirectory = (File.GetAttributes(FileFullPath) & FileAttributes.Directory) == FileAttributes.Directory;
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

    public string? FileFullPath { get; }
    public string? FileName { get; }
    public bool? IsDirectory { get; }
    public bool? IsFileHandle { get; }

    /// <summary>
    /// Try to get the absolute path of the file. Traverses filesystem links (e.g. symbolic, junction) to get the 'real' path.
    /// </summary>
    /// <returns>If successful, returns a path string formatted as 'X:\dir\file.ext' or 'X:\dir'</returns>
    /// <exception cref="FileNotFoundException(string, string)">The path '{fullName}' was not found when querying a file handle.</exception>
    /// <exception cref="OutOfMemoryException(string)">Failed to query path from file handle. Insufficient memory to complete the operation.</exception>
    /// <exception cref="ArgumentException(string)">Failed to query path from file handle. Invalid flags were specified for dwFlags.</exception>
    private unsafe string TryGetFinalPath()
    {
        if (ProcessId == 4) throw new InvalidOperationException("Cannot access handle object information if handle is held by System (PID 4)");

        /// Return the normalized drive name. This is the default.
        uint bufLength = (uint)short.MaxValue;
        var buffer = Marshal.AllocHGlobal((int)bufLength);
        PWSTR fullName = new((char*)buffer);
        var processHandle = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, false, ProcessId);
        if (processHandle is null || processHandle?.IsInvalid == true)
            throw new Win32Exception();

        if (!DuplicateHandle(processHandle, new SafeFileHandle((nint)HandleValue, false), Process.GetCurrentProcess().SafeHandle, out SafeFileHandle? dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS))
            throw new Win32Exception();

        uint length = GetFinalPathNameByHandle(dupHandle, fullName, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);

        if (length != 0)
        {
            while (length > bufLength)
            {
                // buffer was too small. Reallocate buffer with size matched 'length' and try again
                buffer = Marshal.ReAllocHGlobal(buffer, (IntPtr)length);
                fullName = new((char*)buffer);

                bufLength = GetFinalPathNameByHandle(dupHandle, fullName, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);
            }
            return fullName.ToString();
        }
        else
        {
            Win32ErrorCode error = (Win32ErrorCode)Marshal.GetLastWin32Error();
            Debug.Print(error.GetMessage());

            /* Hold up. Let's free our memory before throwing exceptions. */
            Marshal.FreeHGlobal(buffer);

            throw error switch
            {
                Win32ErrorCode.ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{fullName}' was not found when querying a file handle.", fileName: fullName.ToString()), // Removable storage, deleted item, network shares, et cetera
                Win32ErrorCode.ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation."), // unlikely, but possible if system has little free memory
                Win32ErrorCode.ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags."), // possible only if FILE_NAME_NORMALIZED (0) is invalid
                _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path."),
            };
        }
    }

    public override string ToString()
    {
        string[] exLog = ExceptionLog.Cast<string>().ToArray();
        for (int i = 0; i < exLog.Length; i++)
        {
            exLog[i] = $" {exLog[i]}".Replace("\n", "\n    ");
        }

        return @$"{GetType().Name} hash:{GetHashCode()}
        {nameof(CreatorBackTraceIndex)} : {CreatorBackTraceIndex}
        {nameof(FileFullPath)}          : {FileFullPath}
        {nameof(IsDirectory)}           : {IsDirectory}
        {nameof(FileName)}              : {FileName}
        {nameof(GrantedAccess)}         : {GrantedAccess}
        {nameof(handle)}                : {handle}
        {nameof(HandleObjectType)}      : {HandleObjectType}
        {nameof(HandleValue)}           : {HandleValue}
        {nameof(IsClosed)}              : {IsClosed}
        {nameof(IsFileHandle)}          : {IsFileHandle}
        {nameof(IsInvalid)}             : {IsInvalid}
        {nameof(Object)}                : {Object}
        {nameof(ProcessCommandLine)}    : {ProcessCommandLine}
        {nameof(ProcessId)}             : {ProcessId}
        {nameof(ProcessMainModulePath)} : {ProcessMainModulePath}
        {nameof(ProcessName)}           : {ProcessName}
        {nameof(ExceptionLog)}          : ...        
        " + exLog;
    }
}
