using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.SystemInformation;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;
using static Windows.Win32.PS_PROTECTION.PS_PROTECTED_TYPE;
using Code = PInvoke.NTSTATUS.Code;
using Env = System.Environment;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace deadlock_dotnet_sdk.Domain;

public partial class ProcessInfo
{
    private bool canGetQueryLimitedInfoHandle;
    private bool canGetReadMemoryHandle;
    private (bool? v, Exception? ex) is32BitEmulatedProcess;
    private (int? v, Exception?) parentId;
    private (ProcessAndHostOSArch? arch, Exception? ex) processAndHostOSArch;
    private (ProcessBasicInformation? v, Exception? ex) processBasicInformation;
    private (string? v, Exception? ex) processCommandLine;
    private (ProcessQueryHandle? v, Exception? ex) processHandle;
    private (bool? v, Exception? ex) processIsProtected;
    private (string? v, Exception? ex) processMainModulePath;
    private (string? v, Exception? ex) processName;
    private (PS_PROTECTION? v, Exception? ex) processProtection;
    private readonly int processId;

    internal ProcessInfo(int processId)
    {
        Process = null;
        this.processId = processId;
    }

    public ProcessInfo(Process process)
    {
        Process = process;
    }

    /// <summary>
    /// <para>
    ///     TRUE if the process is...<br/>
    ///     <ul>
    ///         <li>...running under WOW64 on an Intel64, x64, AMD64, or ARM64 processor.</li><br/>
    ///         <li>...a 32-bit application running under 64-bit Windows 10 on ARM.</li><br/>
    ///     </ul>
    /// </para>
    /// <para>
    ///     FALSE if the process is...<br/>
    ///     <ul>
    ///         <li>...running under 32-bit Windows.</li><br/>
    ///         <li>...a 64-bit application running under 64-bit Windows.</li><br/>
    ///     </ul>
    /// </para>
    /// </summary>
    /// <remarks>This property's P/Invoke of IsWow64Process(HANDLE, BOOL) requires a process handle with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION"/> or <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION"/>.</remarks>
    public (bool? v, Exception? ex) Is32BitEmulatedProcess
    {
        get
        {
            if (is32BitEmulatedProcess is (null, null))
            {
                if (ProcessHandle.v is null)
                {
                    InvalidOperationException ex = new("Unable to query Is32BitEmulatedProcess; Failed to open a process handle with the necessary access.", processHandle.ex);
                    processAndHostOSArch = (null, ex);
                    return is32BitEmulatedProcess = (null, ex);
                }
                else if ((ProcessHandle.v.AccessRights & (PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION)) is 0)
                {
                    UnauthorizedAccessException ex = new("Unable to query Is32BitEmulatedProcess; A process handle was opened, but lacked the necessary access rights ", ProcessHandle.ex);
                    processAndHostOSArch = (null, ex);
                    return is32BitEmulatedProcess = (null, ex);
                }
                else if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10586))
                {
                    unsafe
                    {
                        IMAGE_FILE_MACHINE pNativeMachine = default;
                        /** if UNKNOWN, then process architecture is the same as host architecture i.e. process is ARM64 and host is ARM64
                             * So, pProcessMachine will never be I386 or ARM when the host is either of those.
                             * Because the purpose of this property and function call is to determine if we need to use 32-bit or 64-bit definitions, we only care about the following return values:
                             *   IMAGE_FILE_MACHINE_UNKNOWN - The process is running natively. No emulation is taking place.
                             *   IMAGE_FILE_MACHINE_I386    - The process is running through an emulation layer. The host is probably either ARM64 or AMD64.
                             *   IMAGE_FILE_MACHINE_ARM     - The process is running through an emulation layer. The host is probably either ARM64 or AMD64. If it's a Windows ARM32 PE, then it's a UWP app.
                             */
                        if (IsWow64Process2(ProcessHandle.v.Handle, out IMAGE_FILE_MACHINE pProcessMachine, &pNativeMachine))
                        {
                            processAndHostOSArch = ((pProcessMachine, pNativeMachine), null);
                            return is32BitEmulatedProcess = (pProcessMachine is IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_I386 or IMAGE_FILE_MACHINE.IMAGE_FILE_MACHINE_ARM, null);
                        }
                        else
                        {
                            Exception ex = new("Failed to query Is32BitEmulatedProcess.", new Win32Exception());
                            processAndHostOSArch = (null, ex);
                            return is32BitEmulatedProcess = (null, ex);
                        }
                    }
                }
                else if (!Windows.Win32.PInvoke.IsWow64Process(ProcessHandle.v.Handle, out BOOL IsWow64Process))
                {
                    return is32BitEmulatedProcess = (IsWow64Process, null);
                }
                else
                {
                    return is32BitEmulatedProcess = (null, new Win32Exception());
                }
            }
            else
            {
                return is32BitEmulatedProcess;
            }
        }
    }

    /// <summary>The base Process object this instance expands upon.</summary>
    public Process? Process { get; }

    public int ProcessId => Process?.Id ?? processId;

    /// <summary>
    /// The target ISA of the process and the ISA of the host OS.<br/>
    /// -OR-<br/>
    /// The exception thrown when attempting to get these values.
    /// </summary>
    /// <remarks>The value of this property is provided during Get accessor of Is32BitEmulatedProcess</remarks>
    public (ProcessAndHostOSArch? v, Exception? ex) ProcessAndHostOSArch
    {
        get
        {
            if (processAndHostOSArch == default)
            {
                _ = Is32BitEmulatedProcess;
                return processAndHostOSArch;
            }
            else
            {
                return processAndHostOSArch;
            }
        }
    }

    public (ProcessQueryHandle? v, Exception? ex) ProcessHandle
    {
        get
        {
            if (processHandle == default)
            {
                const string exMsg = "Unable to open handle; ";
                // We can't lookup the ProcessProtection without opening a process handle to check the process protection.
                //PROCESS_ACCESS_RIGHTS access = ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected ? PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ;

                try
                {
                    return processHandle = (ProcessQueryHandle.OpenProcessHandle(
                            ProcessId,
                            PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ),
                        null);
                }
                catch (Win32Exception ex) when ((Win32ErrorCode)ex.NativeErrorCode is Win32ErrorCode.ERROR_ACCESS_DENIED)
                {
                    // Before assuming anything, try without PROCESS_VM_READ. Without it, we don't need Debug privilege, but the PEB and all of its recursive members (e.g. Command Line) will be unavailable.
                    const string exAccessMsg = exMsg + " The requested permissions were denied.";
                    string exPermsFirst = Env.NewLine + "First attempt's requested permissions: " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION) + ", " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ);

                    try
                    {
                        return processHandle = (ProcessQueryHandle.OpenProcessHandle(ProcessId, PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION), null);
                    }
                    catch (Win32Exception ex2) when ((Win32ErrorCode)ex.NativeErrorCode is Win32ErrorCode.ERROR_ACCESS_DENIED)
                    {
                        // Debug Mode could not be enabled? Was SE_DEBUG_NAME denied to user or is current process not elevated?
                        string exPermsSecond = Env.NewLine + "Second attempt's requested permissions: " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION);
                        return processHandle = (null, new UnauthorizedAccessException(exAccessMsg + exPermsFirst + exPermsSecond, ex2));
                    }
                    catch (Exception ex2)
                    {
                        return processHandle = (null, new AggregateException(exMsg + " Permissions were denied and an unknown error occurred.", new Exception[] { ex, ex2 }));
                    }
                }
                catch (Win32Exception ex) when ((Win32ErrorCode)ex.NativeErrorCode is Win32ErrorCode.ERROR_INVALID_PARAMETER)
                {
                    return processHandle = (null, new ArgumentException(exMsg + " A process with ID " + ProcessId + " could not be found. The process may have exited.", ex));
                }
                catch (Exception ex)
                {
                    // unknown error
                    return processHandle = (null, new Exception(exMsg + " An unknown error occurred.", ex));
                }
            }
            else
            {
                return processHandle;
            }
        }
    }

    /// <summary>
    /// Using a SafeProcessHandle with PROCESS_QUERY_LIMITED_INFORMATION access, copy the target process's PROCESS_BASIC_INFORMATION.<br/>
    /// If the operation succeeds and SafeProcessHandle also has PROCESS_READ_VM access, additional data (e.g. CommandLine) is copied.
    /// </summary>
    /// TODO: implement custom Exception types
    public unsafe void GetPropertiesViaProcessHandle()
    {
        if (ProcessHandle.v is null || ProcessHandle.ex is not null)
        {
            var ex = new Exception("Unable to query process info; Failed to open a process handle with the necessary access rights.", ProcessHandle.ex);
            processBasicInformation = (null, ex);
            parentId = (null, ex);
            processCommandLine = (null, ex);
            return;
        }

        canGetQueryLimitedInfoHandle = (ProcessHandle.v.AccessRights & PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION) != 0;
        canGetReadMemoryHandle = (ProcessHandle.v.AccessRights & PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ) != 0;

        if (!canGetQueryLimitedInfoHandle)
            throw new Exception("Unable to query process info with access right 'PROCESS_QUERY_LIMITED_INFORMATION'; The access right was denied to this process.");

        if (Is32BitEmulatedProcess.v is null || Is32BitEmulatedProcess.ex is not null)
            throw new Exception("Unable to query process's basic information; failed to determine process's targeted CPU architecture.", Is32BitEmulatedProcess.ex);

        // allocate one buffer large enough for either 64-bit or 32-bit interop.
        uint returnLength = 0;
        NTSTATUS status;

        /** If Win8.1 or later */

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 3) && processCommandLine is (null, null))
        {
            try
            {
                const uint ProcessCommandLineInformation = 60u;
                uint bufferLength = (uint)Marshal.SizeOf<UNICODE_STRING>() + 2048u;
                using SafeBuffer<byte> bufferCmdLine = new(numBytes: bufferLength);

                status = NtQueryInformationProcess(
                    ProcessHandle.v,
                    (PROCESSINFOCLASS)ProcessCommandLineInformation,
                    (void*)bufferCmdLine.DangerousGetHandle(),
                    (uint)bufferCmdLine.ByteLength,
                    ref returnLength
                    );

                while ((status = NtQueryInformationProcess(ProcessHandle.v, (PROCESSINFOCLASS)ProcessCommandLineInformation, (void*)bufferCmdLine.DangerousGetHandle(), bufferLength, ref returnLength))
                    .Code is Code.STATUS_INFO_LENGTH_MISMATCH)
                {
#if DEBUG
                    Trace.TraceInformation(
                        "bufferLength: " + bufferCmdLine.ByteLength + Env.NewLine +
                        "returnLength: " + returnLength);
#endif
                    // !WARNING may throw OutOfMemoryException; ReAllocHGlobal received a null pointer, but didn't check the error code
                    // the native call to LocalReAlloc (via Marshal.ReAllocHGlobal) sometimes returns a null pointer. This is a Legacy function. Why does .NET not use malloc/realloc?
                    bufferCmdLine.Reallocate(numBytes: returnLength);
                    // none of these helped debug that internal error...
                    //var pinerr = Marshal.GetLastPInvokeError();
                    //var syserr = Marshal.GetLastSystemError();
                    //var winerr = Marshal.GetLastWin32Error();
                }

                processCommandLine = status.IsSuccessful
                    ? (bufferCmdLine.Read<UNICODE_STRING>(0).ToStringLength() ?? string.Empty, null)
                    : throw new NTStatusException(status); // thrown, not assigned. Is the stack trace assigned if the exception is not thrown?
            }
            catch (Exception ex)
            {
                processCommandLine = (null, ex);
            }
        }

        try
        {
            using SafeBuffer<byte> bufferPBI = new(numBytes: (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION64>());
            /** // ! this code will break if the host or process architecture isn't ARM32, AARCH64 (ARM64), i386 (x86), or AMD64/x86_x64.
             *  IA64 (Intel Itanium) and ARMNT (ARM32 Thumb-2 Little Endian) are the most likely culprits.
             */
            /* Do we need to call NtWow64QueryInformationProcess64? */
            if (Env.Is64BitOperatingSystem && !Env.Is64BitProcess && Is32BitEmulatedProcess.v is false) // yes
            {
                while ((status = NtWow64QueryInformationProcess64(ProcessHandle.v, PROCESSINFOCLASS.ProcessBasicInformation, (void*)bufferPBI.DangerousGetHandle(), (uint)bufferPBI.ByteLength, &returnLength)).Code is Code.STATUS_INFO_LENGTH_MISMATCH or Code.STATUS_BUFFER_TOO_SMALL or Code.STATUS_BUFFER_OVERFLOW)
                    bufferPBI.Reallocate(numBytes: returnLength);

                if (status.Code is not Code.STATUS_SUCCESS)
                    throw new NTStatusException(status, "NtWow64QueryInformationProcess64 failed to query a process's basic information; " + status.Message);

                processBasicInformation = (new ProcessBasicInformation(bufferPBI.Read<PROCESS_BASIC_INFORMATION64>(0)), null);
            }
            else
            {
                while ((status = NtQueryInformationProcess(ProcessHandle.v, PROCESSINFOCLASS.ProcessBasicInformation, (void*)bufferPBI.DangerousGetHandle(), (uint)bufferPBI.ByteLength, ref returnLength)).Code is Code.STATUS_INFO_LENGTH_MISMATCH or Code.STATUS_BUFFER_TOO_SMALL or Code.STATUS_BUFFER_OVERFLOW)
                    bufferPBI.Reallocate(returnLength + (uint)IntPtr.Size);

                if (status.Code is not Code.STATUS_SUCCESS)
                    throw new NTStatusException(status, "NtQueryInformationProcess failed to query a process's basic information; " + status.Message);

                if ((Env.Is64BitOperatingSystem && Is32BitEmulatedProcess.v is true) || (!Env.Is64BitOperatingSystem)) // that process is 32-bit
                    processBasicInformation = (new ProcessBasicInformation(bufferPBI.Read<PROCESS_BASIC_INFORMATION32>(0)), null);
                else
                    processBasicInformation = (new ProcessBasicInformation(bufferPBI.Read<PROCESS_BASIC_INFORMATION64>(0)), null);
            }
        }
        catch (Exception ex)
        {
            processBasicInformation = (null, ex);
        }

        if (processBasicInformation.v is not null)
        {
            /// fields/props to assign to if default and ProcessHandle has PROCESS_READ_VM:
            /// <see cref="parentId"/>, <see cref="processCommandLine"/>
            if (parentId is (null, null))
                parentId = ((int)processBasicInformation.v.ParentProcessId, null);

            // if any field requires PROCESS_READ_VM and ProcessHandle lacks it, assign the exception here.
            if (!canGetReadMemoryHandle)
            {
                try
                {
                    throw new UnauthorizedAccessException("Unable to copy process's PEB and child objects; Failed to open SafeProcessHandle with PROCESS_VM_READ access.", ProcessHandle.ex);
                }
                catch (Exception ex)
                {
                    if (processCommandLine is (null, null))
                        processCommandLine = (null, ex);
                }
            }
            else
            {
                try
                {
                    //var peb = processBasicInformation.v.GetPEB(ProcessHandle.v);
                    //var procParams = peb.GetUserProcessParameters(ProcessHandle.v);
                    var procParams = processBasicInformation.v.GetPEB(ProcessHandle.v).GetUserProcessParameters(ProcessHandle.v);

                    if (processCommandLine is (null, null))
                        processCommandLine = (procParams.GetCommandLine(ProcessHandle.v), null);
                }
                catch (Exception ex)
                {
                    if (processCommandLine is (null, null))
                        processCommandLine = (null, ex);
                }
            }
        }
        else
        {
            try
            {
                throw new NullReferenceException("Unable to retrieve data; This process's ProcessBasicInformation could not be retrieved.");
            }
            catch (Exception ex)
            {
                if (parentId is (null, null))
                    parentId = (null, ex);
                if (processCommandLine is (null, null))
                    processCommandLine = (null, ex);
            }
        }
    }

    /// <summary>
    /// The ID of the process that created/started this object's Process. Used for building tree-leaf UIs.<br/>
    /// Source: PROCESS_BASIC_INFORMATION (this.ProcessBasicInformation)
    /// </summary>
    /// <remarks>'v' will only be null for fake processes i.e. System Idle Process, Interrupts. Check if 'ex' is null to determine successful operation.</remarks>
    /// TODO: ProcessBasicInformation
    /// TODO: check field PROCESS_BASIC_INFORMATION.inheritedFromUniqueProcessId
    public (int? v, Exception? ex) ParentId
    {
        get
        {
            if (parentId is (null, null))
                GetPropertiesViaProcessHandle();

            return parentId;
        }
    }

    //public bool ProcessIs64Bit { get; } // unused, for now

    public unsafe (bool? v, Exception? ex) ProcessIsProtected => processIsProtected == default
                ? ProcessProtection.v is not null
                    ? (processIsProtected = (ProcessProtection.v.Value.Type > PsProtectedTypeNone, null))
                    : (processIsProtected = (null, new Exception("ProcessProtection query failed.", ProcessProtection.ex)))
                : processIsProtected;

    public unsafe (PS_PROTECTION? v, Exception? ex) ProcessProtection
    {
        get
        {
            if (processProtection == default)
            {
                const uint ProcessProtectionInformation = 61; // Retrieves a BYTE value indicating the type of protected process and the protected process signer.
                PS_PROTECTION protection = default;
                uint retLength = 0;

                using SafeProcessHandle? hProcess = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)ProcessId);
                NTSTATUS status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)ProcessProtectionInformation, &protection, 1, ref retLength);

                if (status.Code is not Code.STATUS_SUCCESS)
                    return processProtection = (null, new NTStatusException(status));
                else
                    return processProtection = (protection, null);
            }
            else
            {
                return processProtection;
            }
        }
    }

    // TODO: ProcessBasicInformation and recursive members
    internal (ProcessBasicInformation? v, Exception? ex) ProcessBasicInformation
    {
        get
        {
            if (processBasicInformation == default)
            {
                GetPropertiesViaProcessHandle();
                return processBasicInformation;
            }
            else
            {
                return processBasicInformation;
            }
        }
    }

    /// <summary>
    ///
    /// </summary>
    /// TODO: rework for ProcessBasicInformation
    public (string? v, Exception? ex) ProcessCommandLine
    {
        get
        {
            if (processCommandLine == default)
            {
                return ProcessProtection.v?.Type switch
                {
                    PsProtectedTypeNone or PsProtectedTypeProtectedLight => processCommandLine = TryGetProcessCommandLine(),
                    PsProtectedTypeProtected => processCommandLine = (null, new UnauthorizedAccessException("ProcessCommandLine cannot be queried or copied; the process's Protection level prevents access to the process's command line.")),
                    _ => processCommandLine = (null, new InvalidOperationException("ProcessCommandLine cannot be queried or copied; Failed to query the process's protection."))
                };
            }
            else
            {
                return processCommandLine;
            }
        }
    }

    /// <summary>
    /// The full file path of the handle-owning process's main module (the executable file) or an exception if the Get operation failed.
    /// </summary>
    /// <value>
    /// v: If the query succeeded, the full file path of the process's main module, the executable file.<br/>
    /// ex: If the query failed, the error encountered when attempting to query the full file path of the process's main module.
    /// </value>
    /// <remarks>If ProcessProtection.v is null, returns InvalidOperationException. If Protected, returns UnauthorizedAccessException. The queryable details of protected processes (System, Registry, etc.) are limited..</remarks>
    public (string? v, Exception? ex) ProcessMainModulePath
    {
        get
        {
            if (processMainModulePath == default)
            {
                if (ProcessProtection.v is not null)
                {
                    if (ProcessProtection.v.Value.Type is PsProtectedTypeNone or PsProtectedTypeProtectedLight)
                    {
                        try
                        {
                            return processMainModulePath = (GetFullProcessImageName((uint)ProcessId), null);
                        }
                        catch (Win32Exception ex) when (ex.ErrorCode == 31)
                        {
                            return processMainModulePath = (null, new InvalidOperationException("Process has exited, so the requested information is not available.", ex));
                        }
                        catch (Exception ex)
                        {
                            return processMainModulePath = (null, ex);
                        }
                    }
                    else
                    {
                        return processMainModulePath = (null, new UnauthorizedAccessException("Unable to query ProcessMainModulePath; The process is protected."));
                    }
                }
                else
                {
                    return processMainModulePath = (null, new InvalidOperationException("Unable to query ProcessMainModulePath; Failed to query the process's protection:" + NewLine + ProcessProtection.ex));
                }
            }
            else
            {
                return processMainModulePath;
            }
        }
    }

    public (string? v, Exception? ex) ProcessName
    {
        get
        {
            if (processName == default)
            {
                switch (ProcessId)
                {
                    case 0:
                        return processName = ("System Idle Process", null);
                    case 4:
                        return processName = ("System", null);
                    default:
                        try
                        {
                            var proc = Process.GetProcessById(ProcessId);
                            if (proc.HasExited)
                                return processName = (null, new InvalidOperationException("Process has exited, so the requested information is not available."));
                            else return processName = (Process.GetProcessById(ProcessId).ProcessName, null);
                        }
                        catch (Exception ex)
                        {
                            return processName = (null, ex);
                        }
                }
            }
            else
            {
                return processName;
            }
        }
    }

    //public bool ProcessIs64Bit { get; } // unused, for now

    /// <summary>
    /// A wrapper for QueryFullProcessImageName, a system function that circumvents 32-bit process limitations when permitted the PROCESS_QUERY_LIMITED_INFORMATION right.
    /// </summary>
    /// <param name="processId">The ID of the process to open. The resulting SafeProcessHandle is opened with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION"/></param>
    /// <returns>The path to the executable image.</returns>
    /// <exception cref="ArgumentException">The process handle <paramref name="hProcess"/> is invalid</exception>
    /// <exception cref="Win32Exception">QueryFullProcessImageName failed. See Exception message for details.</exception>
    /// <exception cref="UnauthorizedAccessException">Failed to open process handle for processId; </exception>
    private unsafe static string GetFullProcessImageName(uint processId)
    {
        uint size = 260 + 1;
        uint bufferLength = size;

        using SafeProcessHandle? hProcess = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (hProcess.IsInvalid)
            throw new UnauthorizedAccessException("Cannot query process's filename.", new Win32Exception());

        using PWSTR buffer = new((char*)Marshal.AllocHGlobal((int)bufferLength));
        if (QueryFullProcessImageName(hProcess, PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32, lpExeName: buffer, ref size))
        {
            return buffer.ToString();
        }
        else if (bufferLength < size)
        {
            using PWSTR newBuffer = Marshal.AllocHGlobal((IntPtr)size);
            if (QueryFullProcessImageName(
                            hProcess,
                            PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32,
                            newBuffer,
                            ref size))
            {
                return newBuffer.ToString(); // newBuffer.Value will not be null here
            }
            else
            {
                throw new Win32Exception(); // this constructor calls Marshal.GetLastPInvokeError() and Marshal.GetPInvokeErrorMessage(int)
            }
        }
        else
        {
            // this constructor calls Marshal.GetLastPInvokeError() and Marshal.GetPInvokeErrorMessage(int)
            throw new Win32Exception();
        }
    }

    private (string? v, Exception? ex) TryGetProcessCommandLine()
    {
        if (ProcessId == Env.ProcessId)
            return (Env.CommandLine, null);

        try
        {
            if (!IsDebugModeEnabled())
                Process.EnterDebugMode();
        }
        catch (Exception ex)
        {
            Trace.WriteLine("Failed check if Debug Mode was enabled or failed to enable Debug Mode for the current process." + Env.NewLine + ex.ToString());
        }

        using SafeProcessHandle hProcess = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ, false, (uint)ProcessId);
        if (hProcess.IsInvalid)
            return (null, new Win32Exception());

        try
        {
            return (GetProcessCommandLine(hProcess, Is32BitEmulatedProcess), null);
        }
        catch (Exception ex)
        {
            return (null, ex);
        }
    }

    /// TODO: clean up Exception. Implement custom exceptions?
    /// <summary>Try to get a process's command line from its PEB</summary>
    /// <param name="hProcess">A handle to the target process with the rights PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ</param>
    /// <exception cref="ArgumentException">The provided process handle is invalid.</exception>
    /// <exception cref="Exception">
    ///     IsWow64Process failed to determine if target process is running under WOW. See InnerException.
    ///     -OR-
    ///     NtQueryInformationProcess failed to get a process's command line. See InnerException.
    ///     -OR-
    ///     NtWow64QueryInformationProcess64 failed to get the memory address of another process's PEB. See InnerException.
    ///     -OR-
    ///     NtWow64ReadVirtualMemory64 failed to copy another process's PEB to this process. See InnerException.
    ///     -OR-
    ///     NtWow64ReadVirtualMemory64 failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process. See InnerException.
    ///     -OR-
    ///     NtWow64ReadVirtualMemory64 failed to copy another process's command line character string to this process. See InnerException.
    ///     -OR-
    ///     NtQueryInformationProcess failed to get the memory address of another process's PEB. See InnerException.
    ///     -OR-
    ///     ReadProcessMemory failed to copy another process's PEB to this process. See InnerException.
    ///     -OR-
    ///     ReadProcessMemory failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process. See InnerException.
    ///     -OR-
    ///     ReadProcessMemory failed to copy another process's command line character string to this process. See InnerException.
    ///     -OR-
    ///     </exception>
    /// <exception cref="OutOfMemoryException">ReAllocHGlobal received a null pointer, but didn't check the error code. This is not a real OutOfMemoryException</exception>
    private unsafe static string GetProcessCommandLine(SafeProcessHandle hProcess, (bool? v, Exception? ex) isWow64Process)
    {
        if (hProcess.IsInvalid)
            throw new ArgumentException("The provided process handle is invalid.", paramName: nameof(hProcess));

        if (isWow64Process.ex is not null)
            throw new Exception("Failed to determine target process is running under WOW. See InnerException.", isWow64Process.ex);

        bool targetIs32BitProcess = isWow64Process.v is true;
        bool weAre32BitAndTheyAre64Bit = !Env.Is64BitProcess && !targetIs32BitProcess;
        bool weAre64BitAndTheyAre32Bit = Env.Is64BitProcess && targetIs32BitProcess;
        NTSTATUS status;
        uint returnLength = 0;
        ulong bytesRead;

        /** If Win8.1 or later */
        if (OperatingSystem.IsWindowsVersionAtLeast(6, 3))
        {
            const uint ProcessCommandLineInformation = 60u;
            uint bufferLength = (uint)Marshal.SizeOf<UNICODE_STRING>() + 2048u;
            using SafeBuffer<byte> safeBuffer = new(numBytes: bufferLength);

            status = NtQueryInformationProcess(
                hProcess,
                (PROCESSINFOCLASS)ProcessCommandLineInformation,
                (void*)safeBuffer.DangerousGetHandle(),
                bufferLength,
                ref returnLength
                );

            if (status == Code.STATUS_INFO_LENGTH_MISMATCH)
            {
#if DEBUG
                Console.Out.WriteLine(
                    $"bufferLength: {bufferLength}\n" +
                    $"returnLength: {returnLength}");
                bufferLength = returnLength;
#endif
                try
                {
                    // the native call to LocalReAlloc (via Marshal.ReAllocHGlobal) sometimes returns a null pointer. This is a Legacy function. Why does .NET not use malloc/realloc?
                    //pString->Buffer = new((char*)Marshal.ReAllocHGlobal((IntPtr)pString->Buffer.Value, (IntPtr)bufferLength));
                    safeBuffer.Reallocate(numBytes: returnLength);
                }
                catch (OutOfMemoryException) // ReAllocHGlobal received a null pointer, but didn't check the error code
                {
                    // none of these were of interest...
                    //var pinerr = Marshal.GetLastPInvokeError();
                    //var syserr = Marshal.GetLastSystemError();
                    //var winerr = Marshal.GetLastWin32Error();
                    throw;
                }

                status = NtQueryInformationProcess(
                    hProcess,
                    (PROCESSINFOCLASS)ProcessCommandLineInformation,
                    (void*)safeBuffer.DangerousGetHandle(),
                    bufferLength,
                    ref returnLength
                    );
            }

            if (status.IsSuccessful)
                return safeBuffer.Read<UNICODE_STRING>(0).ToStringZ() ?? string.Empty;
            else
                throw new Exception("NtQueryInformationProcess failed to get a process's command line. See InnerException.", new NTStatusException(status));
        }
        else /** Read CommandLine from PEB's Process Parameters */
        {
            /** if our process is 32-bit and the target process is 64-bit, use a workaround.
                The following blocks use a hybrid of SystemInformer's solution (PhGetProcessCommandLine) and the alternative provided at https://stackoverflow.com/a/14012919/14894786.
                All comments inside the code blocks are from either source.
            */
            if (weAre32BitAndTheyAre64Bit) /** This process is 32-bit, that process is 64-bit */
            {
                using SafeBuffer<byte> buffer = new(numBytes: 0);
                PROCESS_BASIC_INFORMATION64 basicInfo = default;
                PEB64 peb = default;
                RTL_USER_PROCESS_PARAMETERS64 parameters = default;

                // Get the PEB address.
                buffer.Initialize<PROCESS_BASIC_INFORMATION64>(numElements: 1);
                status = NtWow64QueryInformationProcess64(
                    hProcess,
                    PROCESSINFOCLASS.ProcessBasicInformation,
                    &basicInfo,
                    (uint)buffer.ByteLength,
                    &returnLength);
                buffer.Initialize(numBytes: returnLength);
                byte* pointer = null;
                buffer.AcquirePointer(ref pointer);
                status = NtWow64QueryInformationProcess64(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, pointer, (uint)buffer.ByteLength, &returnLength);
                buffer.ReleasePointer();
                if (status.IsSuccessful)
                {
                    basicInfo = buffer.Read<PROCESS_BASIC_INFORMATION64>(0);
                    buffer.Dispose();
                }
                else
                {
                    throw new Exception("NtWow64QueryInformationProcess64 failed to get the memory address of another process's PEB. See InnerException.", new NTStatusException(status));
                }

                // copy PEB
                if (!(status = NtWow64ReadVirtualMemory64(hProcess, (UIntPtr64)basicInfo.PebBaseAddress, &peb, (ulong)Marshal.SizeOf(peb), &bytesRead)).IsSuccessful)
                    throw new Exception("NtWow64ReadVirtualMemory64 failed to copy another process's PEB to this process. See InnerException.", new NTStatusException(status));

                // Copy RTL_USER_PROCESS_PARAMETERS.
                if (!(status = NtWow64ReadVirtualMemory64(hProcess, (UIntPtr64)peb.ProcessParameters, &parameters, (ulong)Marshal.SizeOf(parameters), &bytesRead)).IsSuccessful)
                    throw new Exception("NtWow64ReadVirtualMemory64 failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process. See InnerException.", new NTStatusException(status));

                using UNICODE_STRING cmdLine = new()
                {
                    MaximumLength = parameters.CommandLine.MaximumLength,
                    Length = parameters.CommandLine.Length,
                    Buffer = (char*)Marshal.AllocHGlobal(parameters.CommandLine.MaximumLength)
                };

                if (!(status = NtWow64ReadVirtualMemory64(hProcess, (UIntPtr64)parameters.CommandLine.Buffer, cmdLine.Buffer.Value, cmdLine.MaximumLength, &bytesRead)).IsSuccessful)
                    throw new Exception("NtWow64ReadVirtualMemory64 failed to copy another process's command line character string to this process. See InnerException.", new NTStatusException(status));

                return cmdLine.ToStringLength();
            }
            else if (weAre64BitAndTheyAre32Bit) /** This is 64-bit, that is 32-bit */
            {
                using SafeBuffer<PROCESS_BASIC_INFORMATION32> buffer = new(numElements: 1);
                PROCESS_BASIC_INFORMATION32 basicInfo = default;
                PEB32 peb = default;
                RTL_USER_PROCESS_PARAMETERS32 parameters = default;

                // Get the PEB address.
                buffer.Initialize<PROCESS_BASIC_INFORMATION32>(numElements: 1);
                status = NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessBasicInformation,
                    &basicInfo,
                    (uint)buffer.ByteLength,
                    ref returnLength);
                while (status == Code.STATUS_INFO_LENGTH_MISMATCH)
                {
                    buffer.Initialize(numBytes: returnLength);
                    byte* pointer = null;
                    buffer.AcquirePointer(ref pointer);
                    status = NtQueryInformationProcess(
                        hProcess,
                        PROCESSINFOCLASS.ProcessBasicInformation,
                        pointer,
                        (uint)buffer.ByteLength,
                        ref returnLength);
                    buffer.ReleasePointer();
                }
                if (status.IsSuccessful)
                {
                    basicInfo = buffer.Read<PROCESS_BASIC_INFORMATION32>(0);
                    buffer.Dispose();
                }
                else
                {
                    throw new Exception("NtQueryInformationProcess failed to get the memory address of another process's PEB. See InnerException.", new NTStatusException(status));
                }

                // copy PEB
                if (!ReadProcessMemory(hProcess, (void*)basicInfo.PebBaseAddress, &peb, (nuint)Marshal.SizeOf(peb), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's PEB to this process. See InnerException.", new NTStatusException(status));

                // Copy RTL_USER_PROCESS_PARAMETERS.
                if (!ReadProcessMemory(hProcess, (void*)peb.ProcessParameters, &parameters, (nuint)Marshal.SizeOf(parameters), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process. See InnerException.", new NTStatusException(status));

                using UNICODE_STRING cmdLine = new()
                {
                    MaximumLength = parameters.CommandLine.MaximumLength,
                    Length = parameters.CommandLine.Length,
                    Buffer = (char*)Marshal.AllocHGlobal(Marshal.SizeOf<char>() * 260)
                };

                if (!ReadProcessMemory(hProcess, (void*)parameters.CommandLine.Buffer, cmdLine.Buffer.Value, cmdLine.MaximumLength, (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's command line character string to this process. See InnerException.", new NTStatusException(status));

                return cmdLine.ToStringLength();
            }
            else /** this process and that process are the same bit architecture */
            {
                using SafeBuffer<PROCESS_BASIC_INFORMATION> buffer = new(numElements: 1);
                PROCESS_BASIC_INFORMATION basicInfo = default;
                PEB peb = default;
                RTL_USER_PROCESS_PARAMETERS parameters = default;

                // Get the PEB address.
                status = NtQueryInformationProcess(
                    hProcess,
                    PROCESSINFOCLASS.ProcessBasicInformation,
                    &basicInfo,
                    (uint)buffer.ByteLength,
                    ref returnLength);
                while (status == Code.STATUS_INFO_LENGTH_MISMATCH)
                {
                    buffer.Initialize(numBytes: returnLength);
                    byte* pointer = null;
                    buffer.AcquirePointer(ref pointer);
                    status = NtQueryInformationProcess(
                        hProcess,
                        PROCESSINFOCLASS.ProcessBasicInformation,
                        pointer,
                        (uint)buffer.ByteLength,
                        ref returnLength);
                    buffer.ReleasePointer();
                }
                if (status.IsSuccessful)
                {
                    basicInfo = buffer.Read<PROCESS_BASIC_INFORMATION>(0);
                    buffer.Dispose();
                }
                else
                {
                    throw new Exception("NtQueryInformationProcess failed to get the memory address of another process's PEB. See InnerException.", new NTStatusException(status));
                }

                // copy PEB
                if (!ReadProcessMemory(hProcess, basicInfo.PebBaseAddress, &peb, (nuint)Marshal.SizeOf(peb), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's PEB to this process. See InnerException.", new NTStatusException(status));

                // Copy RTL_USER_PROCESS_PARAMETERS.
                if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &parameters, (nuint)Marshal.SizeOf(parameters), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process. See InnerException.", new NTStatusException(status));

                using UNICODE_STRING cmdLine = new()
                {
                    MaximumLength = parameters.CommandLine.MaximumLength,
                    Length = parameters.CommandLine.Length,
                    Buffer = (char*)Marshal.AllocHGlobal(Marshal.SizeOf<char>() * 260)
                };

                if (!ReadProcessMemory(hProcess, (void*)parameters.CommandLine.Buffer, cmdLine.Buffer.Value, cmdLine.MaximumLength, (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's command line character string to this process. See InnerException.", new NTStatusException(status));

                return cmdLine.ToStringLength();
            }
        }
    }
}
