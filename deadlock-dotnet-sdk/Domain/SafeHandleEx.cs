using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Threading;
using Windows.Win32.System.WindowsProgramming;
using static Windows.Win32.PInvoke;
using static Windows.Win32.PS_PROTECTION.PS_PROTECTED_TYPE;
using ACCESS_MASK = PInvoke.Kernel32.ACCESS_MASK;
using Code = PInvoke.NTSTATUS.Code;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace deadlock_dotnet_sdk.Domain;

//TODO: check if handle is closed. If true, FileLockerEx can remove this object from its locker list. See relevant TODO in FileLockerEx
/// <summary>
/// A SafeHandleZeroOrMinusOneIsInvalid wrapping a SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX<br/>
/// Before querying for system handles, call <see cref="Process.EnterDebugMode()"/>
/// for access to some otherwise restricted data.
/// NOTE: <see cref="NativeMethods.FindLockingHandles">FindLockingHandles(string, Filter)</see>
/// enters Debug mode before querying handles and other data.
/// </summary>
public class SafeHandleEx : SafeHandleZeroOrMinusOneIsInvalid
{
    protected (string? v, Exception? ex) handleObjectType;
    private (string? v, Exception? ex) objectName;
    private ProcessInfo? processInfo;

    public SafeHandleEx(SafeHandleEx safeHandleEx) : this(safeHandleEx.SysHandleEx)
    { }

    /// <summary>
    /// Initializes a new instance of the <c>SafeHandleEx</c> class from a <see cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"/>, specifying whether the handle is to be reliably released.
    /// </summary>
    /// <param name="sysHandleEx"></param>
    internal SafeHandleEx(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx) : base(false)
    {
        SysHandleEx = sysHandleEx;
        handle = sysHandleEx.HandleValue;
    }

    internal SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX SysHandleEx { get; }

    public unsafe UIntPtr ObjectAddress => SysHandleEx.Object;
    public uint ProcessId => (uint)SysHandleEx.UniqueProcessId;
    public nuint HandleValue => SysHandleEx.HandleValue;
    public ushort CreatorBackTraceIndex => SysHandleEx.CreatorBackTraceIndex;
    /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.GrantedAccess"/>
    public ACCESS_MASK GrantedAccess => SysHandleEx.GrantedAccess;
    public string GrantedAccessString => SysHandleEx.GrantedAccessString;
    /// <summary>The Type of the object as a string.</summary>
    public (string? v, Exception? ex) HandleObjectType
    {
        get
        {
            if (handleObjectType == default)
            {
                var (v, ex) = ProcessInfo.ProcessProtection;
                if (v is null)
                {
                    return handleObjectType = (null, new InvalidOperationException("Unable to query the kernel object's Type; Failed to query the process's protection:" + Environment.NewLine + ex, ex));
                }
                else if (v.Value.Type is PsProtectedTypeNone or PsProtectedTypeProtectedLight)
                {
                    try
                    {
                        return handleObjectType = (SysHandleEx.GetHandleObjectType(), null);
                    }
                    catch (Exception e)
                    {
                        return handleObjectType = (null, e);
                    }
                }
                else
                {
                    return handleObjectType = (null, new UnauthorizedAccessException("Unable to query the kernel object's Type; The process is protected."));
                }
            }
            else
            {
                return handleObjectType;
            }
        }
    }

    /// <summary>
    /// (non-persistent) Pass the handle to GetHandleInformation and check for ERROR_INVALID_HANDLE to determine if the handle is open or closed.
    /// </summary>
    public new bool IsClosed => GetIsClosed();

    private bool GetIsClosed()
    {
        try
        {
            HANDLE_FLAGS flags = GetHandleInformation(this);
        }
        catch (PInvoke.Win32Exception ex) when (ex.NativeErrorCode is Win32ErrorCode.ERROR_INVALID_HANDLE)
        {
            return true;
        }
        catch (PInvoke.Win32Exception ex)
        {
            Trace.TraceError(ex.ToString());
        }
        return false;
    }

    /// <summary>
    /// The name of the object e.g. "\\Device\\HarddiskVolume4\\Repos\\BinToss\\deadlock-dotnet-diagnostics\\deadlock-diagnostics" or "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Nls\\Sorting\\Versions"
    /// </summary>
    /// <example>
    /// ("\\Sessions\\1\\BaseNamedObjects\\SM0:25004:304:WilStaging_02", null)
    /// ("\\Device\\HarddiskVolume4\\Users\\NoahR\\AppData\\Roaming\\Code\\logs\\20230408T181715\\window1\\exthost\\output_logging_20230408T181718\\13-DTDL.log", null)
    /// ("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Nls\\Sorting\\Versions", null)
    /// ("\\Device\\CNG", null)
    /// </example>
    public unsafe (string? v, Exception? ex) ObjectName
    {
        get
        {
            if (objectName == default)
            {
                var (v, ex) = ProcessInfo.ProcessProtection;
                // I'm assuming process protection prohibits access. I've not tested it.
                // This information is not queryable in SystemInformer when a process has Full protection.
                if (v is null)
                    return objectName = (null, new UnauthorizedAccessException("Unable to query ObjectName; Failed to query process's protection level.", ex));
                else if (v.Value.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected)
                    return objectName = (null, new UnauthorizedAccessException("Unable to query ObjectName; The process's protection type prohibits access."));

                uint bufferLength = 1024u;
                using SafeBuffer<OBJECT_NAME_INFORMATION> buffer = new(numBytes: bufferLength);
                NTSTATUS status = default;

                while ((status = NtQueryObject(this,
                                               OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                                               (OBJECT_NAME_INFORMATION*)buffer.DangerousGetHandle(),
                                               bufferLength,
                                               &bufferLength)).Code
                    is Code.STATUS_BUFFER_OVERFLOW or Code.STATUS_INFO_LENGTH_MISMATCH or Code.STATUS_BUFFER_TOO_SMALL)
                {
                    buffer.Reallocate(bufferLength);
                }

                OBJECT_NAME_INFORMATION oni = buffer.Read<OBJECT_NAME_INFORMATION>(0);
                if (oni.Name.Buffer.Value == null)
                    return (null, new NullReferenceException("Bad data was copied to the buffer. The string pointer is null."));

                return status.IsSuccessful
                    ? objectName = (oni.NameAsString, null)
                    : objectName = (null, new NTStatusException(status));
            }
            else
            {
                return objectName;
            }
        }
    }

    public ProcessInfo ProcessInfo => processInfo ??= NativeMethods.Processes.GetProcessById((int)(uint)SysHandleEx.UniqueProcessId);

    /// <summary>A list of exceptions thrown by constructors and other methods of this class.</summary>
    /// <remarks>Use List's methods (e.g. Add) to modify this list.</remarks>
    public List<Exception> ExceptionLog { get; } = new();

    #region Methods

    /// <summary>
    /// Release the system handle.<br/>
    /// ! WARNING !<br/>
    /// If the handle or a duplicate is in use by a driver or other kernel-level software, a function that accesses the now-invalid handle will cause a stopcode (AKA Blue Screen Of Death).
    /// </summary>
    /// <remarks>
    /// See Raymond Chen's devblog article <see href="https://devblogs.microsoft.com/oldnewthing/20070829-00/?p=25363">"Kernel handles are not reference-counted"</see>.
    /// </remarks>
    /// <exception cref="Win32Exception">Failed to open process to duplicate and close object handle.</exception>
    public bool CloseSourceHandle()
    {
        try
        {
            HANDLE rawHProcess;
            using SafeProcessHandle hProcess = new(
                !(rawHProcess = OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, true, ProcessId)).IsNull
                    ? rawHProcess
                    : throw new Win32Exception($"Failed to open process with id {ProcessId} to duplicate and close object handle."),
                true);
            if (!DuplicateHandle(hProcess, this, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_CLOSE_SOURCE))
                throw new Win32Exception("Function DuplicateHandle failed to duplicate the handle");

            dupHandle.Close();
            hProcess.Close();
            // finally, close this SafeHandleEx
            Close();
            return true;
        }
        catch (Exception ex)
        {
            ExceptionLog.Add(ex);
            return false;
        }
    }

    /// <summary>
    /// Release all resources owned by the current process that are associated with this handle.
    /// </summary>
    /// <returns>Returns a bool indicating IsClosed is true</returns>
    protected override bool ReleaseHandle()
    {
        Close();
        return IsClosed;
    }

    #endregion Methods
}
