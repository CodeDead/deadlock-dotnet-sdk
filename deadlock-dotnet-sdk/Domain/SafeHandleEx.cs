using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;
using ACCESS_MASK = PInvoke.Kernel32.ACCESS_MASK;
using Code = PInvoke.NTSTATUS.Code;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace deadlock_dotnet_sdk.Domain;

/// <summary>
/// A SafeHandleZeroOrMinusOneIsInvalid wrapping a SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX<br/>
/// Before querying for system handles, call <see cref="Process.EnterDebugMode()"/>
/// for access to some otherwise restricted data.
/// NOTE: <see cref="NativeMethods.FindLockingHandles">FindLockingHandles(string, Filter)</see>
/// enters Debug mode before querying handles and other data.
/// </summary>
public class SafeHandleEx : SafeHandleZeroOrMinusOneIsInvalid
{
    private string? processCommandLine;

    public SafeHandleEx(SafeHandleEx safeHandleEx) : this(safeHandleEx.SysHandleEx)
    { }

    /// <summary>
    /// Initializes a new instance of the <c>SafeHandleEx</c> class from a <see cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"/>, specifying whether the handle is to be reliably released.
    /// </summary>
    /// <param name="sysHandleEx"></param>
    internal SafeHandleEx(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx) : base(false)
    {
        SysHandleEx = sysHandleEx;
        handle = sysHandleEx.HandleValue;

        try
        {
            HandleObjectType = SysHandleEx.GetHandleObjectType();
        }
        catch (Exception e)
        {
            ExceptionLog.Add(e);
        }

        // Get additional details from the handle's owner process
        try
        {
            /** Open handle for process */
            // PROCESS_QUERY_LIMITED_INFORMATION is necessary for QueryFullProcessImageName
            // PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ for reading PEB from the process's memory space.
            // if we need to duplicate a handle later, we'll use PROCESS_DUP_HANDLE

            if (ProcessId == 0)
            {
                ProcessName = "System Idle Process";
            }
            else if (ProcessId == 4)
            {
                ProcessName = "System";
            }
            else
            {
                try
                {
                    ProcessName = Process.GetProcessById((int)ProcessId).ProcessName;
                }
                catch (Exception e)
                {
                    ExceptionLog.Add(e);
                }

                /** Get main module's full path */
                try
                {
                    ProcessMainModulePath = GetFullProcessImageName(ProcessId);
                }
                catch (Exception e)
                {
                    ExceptionLog.Add(e);
                }

                /** Get Process's name */
                if (!string.IsNullOrWhiteSpace(ProcessMainModulePath))
                    ProcessName = Path.GetFileNameWithoutExtension(ProcessMainModulePath);

                /** Get process's possibly-overwritten command line from the PEB struct in its memory space */
                //ProcessCommandLine = GetProcessCommandLine(ProcessId);
                // moved to property's Get accessor
            }
        }
        catch (Exception e)
        {
            ExceptionLog.Add(e);
        }
    }

    internal NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX SysHandleEx { get; }

    public unsafe UIntPtr Object => SysHandleEx.ObjectPointer;
    public uint ProcessId => (uint)SysHandleEx.UniqueProcessId;
    public nuint HandleValue => SysHandleEx.HandleValue;
    public ushort CreatorBackTraceIndex => SysHandleEx.CreatorBackTraceIndex;
    /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.GrantedAccess"/>
    public ACCESS_MASK GrantedAccess => SysHandleEx.GrantedAccess;
    /// <summary>
    /// The Type of the object as a string.
    /// </summary>
    /// <value></value>
    public string? HandleObjectType { get; }
    //public bool ProcessIs64Bit { get; } // unused, for now
    public string? ProcessCommandLine
    {
        get => processCommandLine ??= GetProcessCommandLine(ProcessId); // if null, call function and assign value
        init { processCommandLine = value; }
    }
    public string? ProcessMainModulePath { get; }
    public string? ProcessName { get; }
    //internal PEB_Ex? PebEx { get; } // Won't need this unless we want to start accessing otherwise unread pointer-type members of the PEB and its children (e.g. PEB_LDR_DATA, CURDIR, et cetera)

    /// <summary>
    /// A list of exceptions thrown by constructors and other methods of this class.<br/>
    /// Intended to explain why the process command line, main module path, and name are unavailable.
    /// </summary>
    /// <remarks>Use List's methods (e.g. Add) to modify this list.</remarks>
    public List<Exception> ExceptionLog { get; } = new();

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

    /// <summary>Invokes <see cref="GetHandleObjectType()"/> and checks if the result is "File".</summary>
    /// <returns>True if the handle is for a file or directory.</returns>
    /// <remarks>Based on source of C/C++ projects <see href="https://www.x86matthew.com/view_post?id=hijack_file_handle">Hijack File Handle</see> and <see href="https://github.com/adamkramer/handle_monitor">Handle Monitor</see></remarks>
    /// <exception cref="Exception">Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. InnerException Message: </exception>
    public (bool? v, Exception? ex) GetIsFileHandle()
    {
        try
        {
            return (HandleObjectType != default && HandleObjectType.v == "File", null);
        }
        catch (Exception ex)
        {
            return (null, new Exception($"Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. InnerException Message: {ex.Message}", ex));
        }
    }

    private (string? v, Exception? ex) TryGetFullProcessImageName()
    {
        try
        {
            return (GetFullProcessImageName(ProcessId), null);
        }
        catch (Win32Exception ex) when (ex.ErrorCode == 31)
        {
            return (null, new InvalidOperationException("Process has exited, so the requested information is not available.", ex));
        }
        catch (Exception ex)
        {
            return (null, ex);
        }
    }

    /// <summary>
    /// A wrapper for QueryFullProcessImageName, a system function that circumvents 32-bit process limitations when permitted the PROCESS_QUERY_LIMITED_INFORMATION right.
    /// </summary>
    /// <param name="processId">The ID of the process to open. The resulting SafeProcessHandle is opened with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION"/></param>
    /// <returns>The path to the executable image.</returns>
    /// <exception cref="ArgumentException">The process handle <paramref name="hProcess"/> is invalid</exception>
    /// <exception cref="Win32Exception">QueryFullProcessImageName failed. See Exception message for details.</exception>
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

    private static (string? v, Exception? ex) GetProcessCommandLine(uint processId)
    {
        if (processId == (uint)Environment.ProcessId)
            return (Environment.CommandLine, null);

        Exception? exceptionData = default;
        try
        {
            if (!IsDebugModeEnabled())
                Process.EnterDebugMode();
        }
        catch (Exception ex)
        {
            exceptionData = ex; // What to do with this exception?
        }

        using SafeProcessHandle hProcess = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ, false, processId);
        if (hProcess.IsInvalid)
            return (null, new Win32Exception());

        try
        {
            //todo: amend GetProcessCommandLine commit
            return (GetProcessCommandLine(hProcess), null);
        }
        catch (Exception ex)
        {
            return (null, ex);
        }
    }

    /// <summary>Try to get a process's command line from its PEB</summary>
    /// <param name="hProcess">A handle to the target process with the rights PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ</param>
    /// <exception cref="NotImplementedException">Reading a 64-bit process's PEB from a 32-bit process (under WOW64) is not yet implemented.</exception>
    /// <exception cref="Win32Exception">Failed to read the process's PEB in memory. While trying to read the PEB, the operation crossed into an area of the process that is inaccessible.</exception>
    /// <exception cref="Exception">NtQueryInformationProcess failed to query the process's 'PROCESS_BASIC_INFORMATION'</exception>
    /// <exception cref="OutOfMemoryException">ReAllocHGlobal received a null pointer, but didn't check the error code. This is not a real OutOfMemoryException</exception>
    private unsafe static string GetProcessCommandLine(SafeProcessHandle hProcess)
    {
        if (hProcess.IsInvalid)
            throw new ArgumentException("The provided process handle is invalid.", paramName: nameof(hProcess));

        if (!IsWow64Process(hProcess, out BOOL targetIs32BitProcess))
            throw new Win32Exception();

        bool weAre32BitAndTheyAre64Bit = !Environment.Is64BitProcess && !targetIs32BitProcess;
        bool weAre64BitAndTheyAre32Bit = Environment.Is64BitProcess && targetIs32BitProcess;
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

                    status = NtQueryInformationProcess(
                        hProcess,
                        (PROCESSINFOCLASS)ProcessCommandLineInformation,
                        (void*)safeBuffer.DangerousGetHandle(),
                        bufferLength,
                        ref returnLength
                        );
                }
                catch (OutOfMemoryException) // ReAllocHGlobal received a null pointer, but didn't check the error code
                {
                    // none of these were of interest...
                    //var pinerr = Marshal.GetLastPInvokeError();
                    //var syserr = Marshal.GetLastSystemError();
                    //var winerr = Marshal.GetLastWin32Error();
                    throw;
                }
            }

            if (status.IsSuccessful)
                return safeBuffer.Read<UNICODE_STRING>(0).ToStringZ() ?? string.Empty;
            else
                throw new NTStatusException(status);
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
                    throw new Exception("NtWow64QueryInformationProcess64 failed to get the memory address of another process's PEB.", new NTStatusException(status));
                }

                // copy PEB
                if (!(status = NtWow64ReadVirtualMemory64(hProcess, (UIntPtr64)basicInfo.PebBaseAddress, &peb, (ulong)Marshal.SizeOf(peb), &bytesRead)).IsSuccessful)
                    throw new Exception("NtWow64ReadVirtualMemory64 failed to copy another process's PEB to this process.", new NTStatusException(status));

                // Copy RTL_USER_PROCESS_PARAMETERS.
                if (!(status = NtWow64ReadVirtualMemory64(hProcess, (UIntPtr64)peb.ProcessParameters, &parameters, (ulong)Marshal.SizeOf(parameters), &bytesRead)).IsSuccessful)
                    throw new Exception("NtWow64ReadVirtualMemory64 failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process.", new NTStatusException(status));

                using UNICODE_STRING cmdLine = new()
                {
                    MaximumLength = parameters.CommandLine.MaximumLength,
                    Length = parameters.CommandLine.Length,
                    Buffer = (char*)Marshal.AllocHGlobal(parameters.CommandLine.MaximumLength)
                };

                if (!(status = NtWow64ReadVirtualMemory64(hProcess, (UIntPtr64)parameters.CommandLine.Buffer, cmdLine.Buffer.Value, cmdLine.MaximumLength, &bytesRead)).IsSuccessful)
                    throw new Exception("NtWow64ReadVirtualMemory64 failed to copy another process's command line character string to this process.", new NTStatusException(status));

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
                    throw new Exception("NtQueryInformationProcess failed to get the memory address of another process's PEB.", new NTStatusException(status));
                }

                // copy PEB
                if (!ReadProcessMemory(hProcess, (void*)basicInfo.PebBaseAddress, &peb, (nuint)Marshal.SizeOf(peb), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's PEB to this process.", new NTStatusException(status));

                // Copy RTL_USER_PROCESS_PARAMETERS.
                if (!ReadProcessMemory(hProcess, (void*)peb.ProcessParameters, &parameters, (nuint)Marshal.SizeOf(parameters), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process.", new NTStatusException(status));

                using UNICODE_STRING cmdLine = new()
                {
                    MaximumLength = parameters.CommandLine.MaximumLength,
                    Length = parameters.CommandLine.Length,
                    Buffer = (char*)Marshal.AllocHGlobal(Marshal.SizeOf<char>() * 260)
                };

                if (!ReadProcessMemory(hProcess, (void*)parameters.CommandLine.Buffer, cmdLine.Buffer.Value, cmdLine.MaximumLength, (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's command line character string to this process.", new NTStatusException(status));

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
                    throw new Exception("NtQueryInformationProcess failed to get the memory address of another process's PEB.", new NTStatusException(status));
                }

                // copy PEB
                if (!ReadProcessMemory(hProcess, basicInfo.PebBaseAddress, &peb, (nuint)Marshal.SizeOf(peb), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's PEB to this process.", new NTStatusException(status));

                // Copy RTL_USER_PROCESS_PARAMETERS.
                if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &parameters, (nuint)Marshal.SizeOf(parameters), (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's RTL_USER_PROCESS_PARAMETERS to this process.", new NTStatusException(status));

                using UNICODE_STRING cmdLine = new()
                {
                    MaximumLength = parameters.CommandLine.MaximumLength,
                    Length = parameters.CommandLine.Length,
                    Buffer = (char*)Marshal.AllocHGlobal(Marshal.SizeOf<char>() * 260)
                };

                if (!ReadProcessMemory(hProcess, (void*)parameters.CommandLine.Buffer, cmdLine.Buffer.Value, cmdLine.MaximumLength, (nuint*)&bytesRead))
                    throw new Exception("ReadProcessMemory failed to copy another process's command line character string to this process.", new NTStatusException(status));

                return cmdLine.ToStringLength();
            }
        }
    }

    /// <summary>
    /// Release all resources owned by the current process that are associated with this handle.
    /// </summary>
    /// <returns>Returns a bool indicating both <see cref="IsClosed"/> and <see cref="IsInvalid"/> are true</returns>
    protected override bool ReleaseHandle()
    {
        Close();
        return IsClosed;
    }

    internal SafeHandle ToSafeFileHandle() => SysHandleEx.ToSafeFileHandle();
}
