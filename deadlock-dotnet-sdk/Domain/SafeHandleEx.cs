using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;
using static Windows.Win32.PInvoke;

namespace deadlock_dotnet_sdk.Domain;

/// <summary>
/// A SafeHandleZeroOrMinusOneIsInvalid wrapping a SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX<br/>
/// Before querying for system handles, call <see cref="Process.EnterDebugMode()"/> for easier access to restricted data.
/// </summary>
public class SafeHandleEx : SafeHandleZeroOrMinusOneIsInvalid
{
    /// <summary>
    /// Initializes a new instance of the <c>SafeHandleEx</c> class from a <see cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX"/>, specifying whether the handle is to be reliably released.
    /// </summary>
    /// <param name="sysHandleEx"></param>
    internal SafeHandleEx(NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX sysHandleEx) : base(false)
    {
        SysHandleEx = sysHandleEx;
        try
        {
            HandleObjectType = SysHandleEx.GetHandleObjectType();
        }
        catch (Exception e)
        {
            ExceptionLog.Add(e);
        }
        try
        {
            //Process.EnterDebugMode(); Best practice: only call this once.

            /** Open handle for process */
            // PROCESS_QUERY_LIMITED_INFORMATION is necessary for QueryFullProcessImageName
            // PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ for reading PEB from the process's memory space.
            // if we need to duplicate a handle later, we'll use PROCESS_DUP_HANDLE

            HANDLE rawHandle = OpenProcess(
                dwDesiredAccess: PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ,
                bInheritHandle: (BOOL)false,
                dwProcessId: ProcessId
            );

            if (rawHandle.IsNull)
                throw new Win32Exception("Failed to open process handle with access rights 'PROCESS_QUERY_LIMITED_INFORMATION' and 'PROCESS_VM_READ'. The following information will be unavailable: main module full name, process name, ");

            SafeProcessHandle hProcess = new(rawHandle, true);

            /** Get main module's full path */
            ProcessMainModulePath = GetFullProcessImageName(hProcess);

            /** Get Process's name */
            if (!string.IsNullOrWhiteSpace(ProcessMainModulePath))
            {
                ProcessName = Path.GetFileNameWithoutExtension(ProcessMainModulePath);
            }

            /** Get process's possibly-overwritten command line from the PEB struct in its memory space */
            GetProcessCommandLine(hProcess);
        }
        catch (Exception e)
        {
            ExceptionLog.Add(e);
        }
    }

    internal NativeMethods.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX SysHandleEx { get; }

    public unsafe void* Object => SysHandleEx.Object;
    /// <summary>
    /// cast to uint
    /// </summary>
    public uint ProcessId => (uint)SysHandleEx.UniqueProcessId;
    public nuint HandleValue => SysHandleEx.HandleValue;
    public ushort CreatorBackTraceIndex => SysHandleEx.CreatorBackTraceIndex;
    /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.GrantedAccess"/>
    public ACCESS_MASK GrantedAccess => SysHandleEx.GrantedAccess;
    public ushort ObjectTypeIndex => SysHandleEx.ObjectTypeIndex;
    /// <inheritdoc cref="SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.HandleAttributes"/>
    public uint HandleAttributes => SysHandleEx.HandleAttributes;

    /// <summary>
    /// The Type of the object as a string.
    /// </summary>
    /// <value></value>
    public string? HandleObjectType { get; private set; }

    public string? ProcessCommandLine { get; private set; }
    public string? ProcessMainModulePath { get; private set; }
    public string? ProcessName { get; private set; }

    /// <summary>
    /// A list of exceptions thrown by constructors and other methods of this class.<br/>
    /// Intended to explain why the process command line, main module path, and name are unavailable.
    /// </summary>
    /// <remarks>Use List's methods (e.g. Add) to modify this list.</remarks>
    public List<Exception> ExceptionLog { get; } = new();

    /// <summary>
    /// Release the system handle.<br/>
    /// ! WARNING !<br/>
    /// If the handle or a duplicate is in use by a driver or other kernel-level software, a function that accesses the now-invalid handle will cause a stopcode (AKA Blue Screen Of D).
    /// </summary>
    /// <remarks>
    /// See Raymond Chen's devblog article 
    /// <see href="https://devblogs.microsoft.com/oldnewthing/20070829-00/?p=25363">"Kernel handles are not reference-counted"</see>.
    /// </remarks>
    /// <exception cref="Win32Exception">Failed to open process to duplicate and close object handle.</exception>
    public void UnlockSystemHandle()
    {
        HANDLE rawHProcess;
        SafeProcessHandle? hProcess = null;
        try
        {
            if ((rawHProcess = OpenProcess(
                PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE,
                true,
                ProcessId)
                ).IsNull)
            {
                throw new Win32Exception($"Failed to open process with id {ProcessId} to duplicate and close object handle.");
            }

            hProcess = new(rawHProcess, true);
            if (DuplicateHandle(hProcess, this, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, 0, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_CLOSE_SOURCE))
            {
                dupHandle.Close();
                hProcess.Close();

                // finally, close this SafeHandleEx
                Close();
            }
            else
            {
                throw new Win32Exception("Function DuplicateHandle failed to duplicate the handle");
            }
        }
        catch (Exception e)
        {
            ExceptionLog.Add(e);
            if (hProcess is not null)
                hProcess.Close();
        }
    }

    /// <summary>
    /// Try to get a process's command line from its PEB
    /// </summary>
    /// <param name="hProcess">A handle to the target process with the rights PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ</param>
    /// <exception cref="NotImplementedException">Reading a 64-bit process's PEB from a 32-bit process (under WOW64) is not yet implemented.</exception>
    /// <exception cref="Win32Exception">Failed to read the process's PEB in memory. While trying to read the PEB, the operation crossed into an area of the process that is inaccessible.</exception>
    /// <exception cref="Exception">NtQueryInformationProcess failed to query the process's 'PROCESS_BASIC_INFORMATION'</exception>
    private unsafe void GetProcessCommandLine(SafeProcessHandle hProcess)
    {
        /* Get PROCESS_BASIC_INFORMATION */
        uint sysInfoLength = (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
        PROCESS_BASIC_INFORMATION processBasicInfo;
        IntPtr sysInfo = Marshal.AllocHGlobal((int)sysInfoLength);
        NTSTATUS status = (NTSTATUS)0;
        uint retLength = 0;

        if ((status = NtQueryInformationProcess(
            hProcess,
            PROCESSINFOCLASS.ProcessBasicInformation,
            (void*)sysInfo,
            sysInfoLength,
            ref retLength))
            .IsSuccessful)
        {
            processBasicInfo = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(sysInfo);

            // if our process is WOW64, we need to account for different pointer sizes if
            // the target process is 64-bit
            IsWow64Process(hProcess, out BOOL wow64Process);
            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess && wow64Process)
            {
                throw new NotImplementedException("Reading a 64-bit process's PEB from a 32-bit process (under WOW64) is not yet implemented.");
                // too much trouble. If someone else wants to do it, be my guest.
                // https://stackoverflow.com/a/36798492/14894786
                // Reason: if our process is 32-bit, we'd be stuck with 32-bit pointers. 
                // If the PEB's address is in 64-bit address space, we can't access it 
                // because the pointer value we received was truncated from 64 bits to 
                // 32 bits.
            }

            IntPtr buf = Marshal.AllocHGlobal(sizeof(PEB));
            if (ReadProcessMemory(hProcess, processBasicInfo.PebBaseAddress, (void*)buf, (nuint)sizeof(PEB), null))
            {
                PEB peb = Marshal.PtrToStructure<PEB>(buf);
                ProcessCommandLine = (*peb.ProcessParameters).CommandLine.ToStringLength();
            }
            else
            {
                // this calls Marshal.GetLastPInvokeError()
                // https://sourcegraph.com/github.com/dotnet/runtime@main/-/blob/src/libraries/System.Private.CoreLib/src/System/ComponentModel/Win32Exception.cs?L46
                throw new Win32Exception("Failed to read the process's PEB in memory. While trying to read the PEB, the operation crossed into an area of the process that is inaccessible.");
            }
        }
        else
        {
            throw new Exception("NtQueryInformationProcess failed to query the process's 'PROCESS_BASIC_INFORMATION'");
        }
    }

    /// <summary>
    /// A wrapper for QueryFullProcessImageName
    /// </summary>
    /// <param name="hProcess">A SafeProcessHandle opened with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION"/></param>
    /// <returns>The path to the executable image.</returns>
    /// <exception cref="ArgumentException">The process handle <paramref name="hProcess"/> is invalid</exception>
    /// <exception cref="Win32Exception">QueryFullProcessImageName failed. See Exception message for details.</exception>
    private unsafe static string GetFullProcessImageName(SafeProcessHandle hProcess)
    {
        if (hProcess.IsInvalid)
            throw new ArgumentException("The process handle is invalid", nameof(hProcess));

        uint size = 260 + 1;
        uint bufferLength = size;
        string retVal = "";

        using PWSTR buffer = new((char*)Marshal.AllocHGlobal((int)bufferLength));
        if (QueryFullProcessImageName(
            hProcess: hProcess,
            dwFlags: PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32,
            lpExeName: buffer,
            lpdwSize: ref size))
        {
            retVal = buffer.ToString();
        }
        else if (bufferLength < size)
        {
            using PWSTR newBuffer = Marshal.ReAllocHGlobal((IntPtr)buffer.Value, (IntPtr)size);
            if (QueryFullProcessImageName(
                hProcess,
                PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32,
                newBuffer,
                ref size))
            {
                retVal = newBuffer.ToString();
            }
            else
            {
                // this constructor calls Marshal.GetLastPInvokeError() and Marshal.GetPInvokeErrorMessage(int)
                throw new Win32Exception();
            }
        }
        else
        {
            // this constructor calls Marshal.GetLastPInvokeError() and Marshal.GetPInvokeErrorMessage(int)
            throw new Win32Exception();
        }

        // PWSTR instances are freed by their using blocks' finalizers
        return retVal;
    }

    protected override bool ReleaseHandle()
    {
        Close();
        return IsClosed;
    }

    /// <summary>
    /// Serialize the current instance to JSON-formatted text
    /// </summary>
    public override string? ToString() => JsonSerializer.Serialize(this, new JsonSerializerOptions() { WriteIndented = true });
}
