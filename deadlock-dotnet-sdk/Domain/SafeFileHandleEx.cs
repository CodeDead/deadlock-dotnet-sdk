using System.Runtime.InteropServices;
using System.Text.Json;
using Windows.Win32.Foundation;
using Windows.Win32.Storage.FileSystem;
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
            if ((bool)(IsFileHandle = SysHandleEx.IsFileHandle()))
            {
                try
                {
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
        catch (Exception ex)
        {
            ExceptionLog.Add(ex);
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
        /// Return the normalized drive name. This is the default.
        uint bufLength = (uint)short.MaxValue;
        var buffer = Marshal.AllocHGlobal((int)bufLength);
        PWSTR fullName = new((char*)buffer);
        uint length = GetFinalPathNameByHandle(this, fullName, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);

        if (length != 0)
        {
            while (length > bufLength)
            {
                // buffer was too small. Reallocate buffer with size matched 'length' and try again
                buffer = Marshal.ReAllocHGlobal(buffer, (IntPtr)length);
                fullName = new((char*)buffer);

                bufLength = GetFinalPathNameByHandle(ToSafeFileHandle(), fullName, bufLength, FILE_NAME.FILE_NAME_NORMALIZED);
            }
            return fullName.ToString();
        }
        else
        {
            int error = Marshal.GetLastWin32Error();
            const int ERROR_PATH_NOT_FOUND = 3;
            const int ERROR_NOT_ENOUGH_MEMORY = 8;
            const int ERROR_INVALID_PARAMETER = 87; // 0x57

            /* Hold up. Let's free our memory before throwing exceptions. */
            Marshal.FreeHGlobal(buffer);

            throw error switch
            {
                ERROR_PATH_NOT_FOUND => new FileNotFoundException($"The path '{fullName}' was not found when querying a file handle.", fileName: fullName.ToString()), // Removable storage, deleted item, network shares, et cetera
                ERROR_NOT_ENOUGH_MEMORY => new OutOfMemoryException("Failed to query path from file handle. Insufficient memory to complete the operation."), // unlikely, but possible if system has little free memory
                ERROR_INVALID_PARAMETER => new ArgumentException("Failed to query path from file handle. Invalid flags were specified for dwFlags."), // possible only if FILE_NAME_NORMALIZED (0) is invalid
                _ => new Exception($"An undocumented error ({error}) was returned when querying a file handle for its path."),
            };
        }
    }

    public override string ToString()
    {
        return JsonSerializer.Serialize(this, options: new() { WriteIndented = true });
    }
}
