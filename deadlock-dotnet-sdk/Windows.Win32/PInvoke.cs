/// This file supplements code generated by CsWin32
using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using MemInfo32 = Windows.Win32.System.Memory.MEMORY_BASIC_INFORMATION32;
using MemInfo64 = Windows.Win32.System.Memory.MEMORY_BASIC_INFORMATION64;

using NTSTATUS_plus = PInvoke.NTSTATUS;

namespace Windows.Win32;

static partial class PInvoke
{
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
    [global::System.Runtime.Versioning.SupportedOSPlatform("windows5.0")]
    internal unsafe static extern NTSTATUS_plus NtDuplicateObject(
        HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        [Optional] HANDLE TargetProcessHandle,
        [Optional] out HANDLE* TargetHandle,
        global::PInvoke.Kernel32.ACCESS_MASK DesiredAccess,
        uint HandleAttributes,
        uint Options
    );

    /// <returns>If successful and the current process is 32-bit, returns a MEMORY_BASIC_INFORMATION32 structure. If the current process is 64-bit, returns a MEMORY_BASIC_INFORMATION64 structure.</returns>
    /// <inheritdoc cref="__VirtualQuery(void*, void*, SIZE_T)alQuery(`void*, void*, SIZE_T)"/>
    internal static unsafe (MemInfo32 memInfo32, MemInfo64 memInfo64) VirtualQuery(nuint lpAddress)
    {
        var is64bit = Environment.Is64BitProcess;
        SIZE_T bufferSize = default;
        int size64 = default;
        int size32 = default;
        void* pBuffer = null;

        GCHandle h64 = default;
        GCHandle h32 = default;

        if (is64bit)
        {
            //pBuffer = (void*)Marshal.AllocHGlobal(size64);
            size64 = Marshal.SizeOf<MemInfo64>();
            h64 = GCHandle.Alloc(default(MemInfo64), GCHandleType.Pinned);
            bufferSize = __VirtualQuery((void*)lpAddress, (void*)h64.AddrOfPinnedObject(), (SIZE_T)size64);
        }
        else // is 32-bit process
        {
            size32 = Marshal.SizeOf<MemInfo32>();
            h32 = GCHandle.Alloc(default(MemInfo32), GCHandleType.Pinned);
            bufferSize = __VirtualQuery((void*)lpAddress, (void*)h32.AddrOfPinnedObject(), (SIZE_T)size32);
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

                if ((bufferSize = __VirtualQuery((void*)lpAddress, pBuffer, bufferSize)) != 0)
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
    [global::System.Runtime.Versioning.SupportedOSPlatform("windows5.1")]
    private unsafe static extern SIZE_T __VirtualQuery(
        void* lpAddress,
        void* lpBuffer,
        SIZE_T dwLength
    );
}