/// This file supplements code generated by CsWin32
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;
using MemInfo32 = Windows.Win32.System.Memory.MEMORY_BASIC_INFORMATION32;
using MemInfo64 = Windows.Win32.System.Memory.MEMORY_BASIC_INFORMATION64;

namespace Windows.Win32;

static partial class PInvoke
{
    /// <summary>
    /// Check if the current process has been granted Debugger privileges (usually via Process.EnterDebugMode())
    /// </summary>
    /// <returns></returns>
    /// <exception cref="Win32Exception">LookupPrivilegeValue(), </exception>
    public static bool IsDebugModeEnabled()
    {
        if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out LUID seDebugPrivilege))
            throw new Win32Exception();

        PRIVILEGE_SET privileges = new()
        {
            Control = PRIVILEGE_SET_ALL_NECESSARY,
            Privilege = new()
            {
                _0 = new Span<LUID_AND_ATTRIBUTES>(new LUID_AND_ATTRIBUTES[]
                {
                    new()
                    {
                        Attributes = TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED,
                        Luid = seDebugPrivilege,
                    }
                })[0]
            },
            PrivilegeCount = 1U
        };
        try
        {
            using SafeFileHandle hProcess = new(Process.GetCurrentProcess().SafeHandle.DangerousGetHandle(), false);
            using SafeFileHandle tProcess = OpenProcessToken(hProcess, TOKEN_ACCESS_MASK.TOKEN_QUERY);
            // only already-enabled privileges are checked. Those that are present (the token has access to them), but disabled are excluded from the result.
            return PrivilegeCheck(tProcess, ref privileges);
        }
        catch (Exception)
        {
            throw;
        }
    }

    /// <summary>Creates a handle that is a duplicate of the specified source handle.</summary>
    /// <param name="SourceProcessHandle">A handle to the source process for the handle being duplicated.</param>
    /// <param name="SourceHandle">The handle to duplicate.</param>
    /// <param name="TargetProcessHandle">A handle to the target process that is to receive the new handle. This parameter is optional and can be specified as NULL if the DUPLICATE_CLOSE_SOURCE flag is set in Options.</param>
    /// <param name="TargetHandle">A pointer to a HANDLE variable into which the routine writes the new duplicated handle. The duplicated handle is valid in the specified target process. This parameter is optional and can be specified as NULL if no duplicate handle is to be created.</param>
    /// <param name="DesiredAccess">A pointer to a HANDLE variable into which the routine writes the new duplicated handle. The duplicated handle is valid in the specified target process. This parameter is optional and can be specified as NULL if no duplicate handle is to be created.</param>
    /// <param name="HandleAttributes">A ULONG that specifies the desired attributes for the new handle. For more information about attributes, see the description of the Attributes member in OBJECT_ATTRIBUTES.</param>
    /// <param name="Options">
    ///     A set of flags to control the behavior of the duplication operation. Set this parameter to zero or to the bitwise OR of one or more of the following flags.
    ///     | Flag name                   | Description
    ///     | --------------------------- | -----------
    ///     | DUPLICATE_SAME_ATTRIBUTES   | Instead of using the HandleAttributes parameter, copy the attributes from the source handle to the target handle.
    ///     | DUPLICATE_SAME_ACCESS       | Instead of using the DesiredAccess parameter, copy the access rights from the source handle to the target handle.
    ///     | DUPLICATE_CLOSE_SOURCE      | Close the source handle.
    /// </param>
    /// <returns>ZwDuplicateObject returns STATUS_SUCCESS if the call is successful.Otherwise, it returns an appropriate error status code.</returns>
    /// <remarks>
    ///     The source handle is evaluated in the context of the specified source process.The calling process must have PROCESS_DUP_HANDLE access to the source process.The duplicate handle is created in the handle table of the specified target process.The calling process must have PROCESS_DUP_HANDLE access to the target process.
    ///     By default, the duplicate handle is created with the attributes specified by the HandleAttributes parameter, and with the access rights specified by the DesiredAccess parameter. If necessary, the caller can override one or both defaults by setting the DUPLICATE_SAME_ATTRIBUTES and DUPLICATE_SAME_ACCESS flags in the Options parameter.
    ///     If the call to this function occurs in user mode, you should use the name "NtDuplicateObject" instead of "ZwDuplicateObject".
    ///     For calls from kernel-mode drivers, the NtXxx and ZwXxx versions of a Windows Native System Services routine can behave differently in the way that they handle and interpret input parameters.For more information about the relationship between the NtXxx and ZwXxx versions of a routine, see Using Nt and Zw Versions of the Native System Services Routines.
    /// </remarks>
    [DllImport("ntdll.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [SupportedOSPlatform("windows5.0")]
    public unsafe static extern NTSTATUS NtDuplicateObject(
        HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        [Optional] HANDLE TargetProcessHandle,
        [Optional] out HANDLE* TargetHandle,
        global::PInvoke.Kernel32.ACCESS_MASK DesiredAccess,
        uint HandleAttributes,
        uint Options
    );

    /// <returns>If successful and the current process is 32-bit, returns a MEMORY_BASIC_INFORMATION32 structure. If the current process is 64-bit, returns a MEMORY_BASIC_INFORMATION64 structure.</returns>
    /// <inheritdoc cref="VirtualQuery(void*, void*, SIZE_T)alQuery(`void*, void*, SIZE_T)"/>
    /// <remarks>This is currently unused because we don't need this much information about a handle's owning process. However, it would be a shame to remove it entirely.</remarks>
    // TODO: split off into 'C#: Reading 32-bit process's memory from 64-bit and vice versa' project
    public static unsafe (MemInfo32 memInfo32, MemInfo64 memInfo64) VirtualQuery(nuint lpAddress)
    {
        SIZE_T bufferSize = default;
        int size64 = default;
        int size32 = default;
        void* pBuffer = null;

        GCHandle h64 = default;
        GCHandle h32 = default;

        if (Environment.Is64BitProcess)
        {
            //pBuffer = (void*)Marshal.AllocHGlobal(size64);
            size64 = Marshal.SizeOf<MemInfo64>();
            h64 = GCHandle.Alloc(default(MemInfo64), GCHandleType.Pinned);
            bufferSize = VirtualQuery((void*)lpAddress, (void*)h64.AddrOfPinnedObject(), (SIZE_T)size64);
        }
        else // is 32-bit process
        {
            size32 = Marshal.SizeOf<MemInfo32>();
            h32 = GCHandle.Alloc(default(MemInfo32), GCHandleType.Pinned);
            bufferSize = VirtualQuery((void*)lpAddress, (void*)h32.AddrOfPinnedObject(), (SIZE_T)size32);
        }

        if (bufferSize != 0)
        {
            if (bufferSize == (nuint)size32)
            {
                return (memInfo32: *(MemInfo32*)pBuffer, default);
            }
            else if (bufferSize == (nuint)size64)
            {
                pBuffer = (void*)Marshal.AllocHGlobal((nint)bufferSize);

                if ((bufferSize = VirtualQuery((void*)lpAddress, pBuffer, bufferSize)) != 0)
                    return (default, memInfo64: *(MemInfo64*)pBuffer);
                else
                    throw new Win32Exception();
            }
            else
            {
                throw new Exception($"VirtualQuery returned a buffer size ({bufferSize} bytes) that does not match either of two expected sizes ({size32}, {size64}).");
            }
        }
        else
        {
            // VirtualQuery failed
            throw new Win32Exception();
        }
    }

    [DllImport("ntdll.dll", ExactSpelling = true, EntryPoint = "NtWow64QueryInformationProcess64")]
    public static extern unsafe NTSTATUS NtWow64QueryInformationProcess64(
        [In] SafeProcessHandle ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        [Out] void* ProcessInformation,
        [In] uint ProcessInformationLength,
        [Out] uint* ReturnLength
    );

    [DllImport("ntdll.dll", ExactSpelling = true, EntryPoint = "NtWow64ReadVirtualMemory64")]
    public static extern unsafe NTSTATUS NtWow64ReadVirtualMemory64(
        [In] SafeProcessHandle ProcessHandle,
        [In] UIntPtr64 BaseAddress,
        [Out] void* Buffer,
        [In] ulong Size,
        [Out] ulong* NumberOfBytesRead
    );

    /// <inheritdoc cref="OpenProcess(PROCESS_ACCESS_RIGHTS, BOOL, uint)"/>
    /// <returns>A SafeProcessHandle to the </returns>
    [SupportedOSPlatform("windows5.1.2600")]
    public static unsafe SafeProcessHandle OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS dwDesiredAccess, bool bInheritHandle, uint dwProcessId)
    {
        HANDLE __result = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        return new SafeProcessHandle(__result, ownsHandle: true);
    }

    /// <summary>
    /// <para>Retrieves information about a range of pages in the virtual address space of the calling process.</para>
    /// <para>To retrieve information about a range of pages in the address space of another process, use the VirtualQueryEx function.</para>
    /// </summary>
    /// <param name="lpAddress">
    /// <para>A pointer to the base address of the region of pages to be queried. This value is rounded down to the next page boundary. To determine the size of a page on the host computer, use the GetSystemInfo function.</para>
    /// <para>If lpAddress specifies an address above the highest memory address accessible to the process, the function fails with ERROR_INVALID_PARAMETER.</para>
    /// </param>
    /// <param name="lpBuffer">A pointer to a MEMORY_BASIC_INFORMATION structure in which information about the specified page range is returned.</param>
    /// <param name="dwLength">The size of the buffer pointed to by the lpBuffer parameter, in bytes.</param>
    /// <returns>
    /// <para>The return value is the actual number of bytes returned in the information buffer.</para>
    /// <para>If the function fails, the return value is zero.To get extended error information, call GetLastError.
    /// Possible error values include ERROR_INVALID_PARAMETER.</para>
    /// </returns>
    // warning PInvoke005: This API is only available when targeting a specific CPU architecture.AnyCPU cannot generate this API.
    [DllImport("Kernel32.dll", ExactSpelling = true, EntryPoint = "VirtualQuery", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [SupportedOSPlatform("windows5.1")]
    private unsafe static extern SIZE_T VirtualQuery(
        void* lpAddress,
        void* lpBuffer,
        SIZE_T dwLength
    );

    /// <returns>Whether any or all of the specified privileges are enabled in the access token. If the Control member of the PRIVILEGE_SET structure specifies PRIVILEGE_SET_ALL_NECESSARY, this value is TRUE only if all the privileges are enabled; otherwise, this value is TRUE if any of the privileges are enabled.</returns>
    /// <exception cref="Win32Exception"/>
    /// <remarks><inheritdoc cref="PrivilegeCheck(HANDLE, PRIVILEGE_SET*, int*)"/><br/>
    /// An access token contains a list of the privileges held by the account associated with the token. These privileges can be enabled or disabled; most are disabled by default. The PrivilegeCheck function checks only for enabled privileges. To get a list of all the enabled and disabled privileges held by an access token, call the GetTokenInformation function. To enable or disable a set of privileges in an access token, call the AdjustTokenPrivileges function.</remarks>
    /// <inheritdoc cref="PrivilegeCheck(HANDLE, Security.PRIVILEGE_SET*, int*)"/>
    public static bool PrivilegeCheck(SafeHandle ClientToken, ref PRIVILEGE_SET RequiredPrivileges)
        => !PrivilegeCheck(ClientToken, ref RequiredPrivileges, out int pfResult) ? throw new Win32Exception() : (BOOL)pfResult;

    /// <returns><inheritdoc cref="OpenProcessToken(HANDLE, TOKEN_ACCESS_MASK, HANDLE*)" path="/param[@name='TokenHandle']"/></returns>
    /// <inheritdoc cref="OpenProcessToken(SafeHandle, TOKEN_ACCESS_MASK, out SafeFileHandle)"/>
    public static SafeFileHandle OpenProcessToken(SafeFileHandle ProcessHandle, TOKEN_ACCESS_MASK DesiredAccess)
        => OpenProcessToken(ProcessHandle, DesiredAccess, out SafeFileHandle TokenHandle) ? TokenHandle : throw new Win32Exception();

    public static HANDLE_FLAGS GetHandleInformation(SafeHandle hObject) => GetHandleInformation(hObject, out uint flags) ? (HANDLE_FLAGS)flags : throw new Win32Exception();
}
