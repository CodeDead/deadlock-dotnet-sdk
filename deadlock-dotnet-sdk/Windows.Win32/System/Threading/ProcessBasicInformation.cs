using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Code = PInvoke.NTSTATUS.Code;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;

namespace Windows.Win32.System.Threading;

public class ProcessBasicInformation
{
    internal ProcessBasicInformation(PROCESS_BASIC_INFORMATION pbi)
    {
        ExitStatus = pbi.ExitStatus;
        unsafe { PebBaseAddress = Environment.Is64BitProcess ? (null, (ulong)pbi.PebBaseAddress) : ((uint)pbi.PebBaseAddress, null); }
        AffinityMask = Environment.Is64BitProcess ? (null, (ulong)pbi.AffinityMask) : ((uint)pbi.AffinityMask, null);
        BasePriority = pbi.BasePriority;
        ProcessId = pbi.ProcessId;
        ParentProcessId = pbi.ParentProcessId;
    }

    internal ProcessBasicInformation(PROCESS_BASIC_INFORMATION32 pbi)
    {
        ExitStatus = pbi.ExitStatus;
        PebBaseAddress = (pbi.PebBaseAddress, null);
        AffinityMask = (pbi.AffinityMask, null);
        BasePriority = pbi.BasePriority;
        ProcessId = pbi.UniqueProcessId;
        ParentProcessId = pbi.InheritedFromUniqueProcessId;
    }

    internal ProcessBasicInformation(PROCESS_BASIC_INFORMATION64 pbi)
    {
        ExitStatus = pbi.ExitStatus;
        PebBaseAddress = (null, pbi.PebBaseAddress);
        AffinityMask = (null, pbi.AffinityMask);
        BasePriority = pbi.BasePriority;
        ProcessId = (uint)pbi.UniqueProcessId;
        ParentProcessId = (uint)pbi.InheritedFromUniqueProcessId;
    }

    internal (UIntPtr32<PEB32>? w32, UIntPtr64<PEB64>? w64) PebBaseAddress { get; }
    public ProcessEnvironmentBlock? ProcessEnvironmentBlock { get; private set; }

    public NTSTATUS ExitStatus { get; }
    public (uint? w32, ulong? w64) AffinityMask { get; }
    public KPRIORITY BasePriority { get; }
    public uint ProcessId { get; }
    public uint ParentProcessId { get; }

    /// <summary>Read the process's private memory to recursively copy the PEB.</summary>
    /// <param name="hProcess">A handle opened with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ"/>. Requires Debug and/or admin privileges.</param>
    /// <exception cref="AccessViolationException">Read operation failed; The memory region is protected and Read access to the memory region was denied.</exception>
    /// <exception cref="NullReferenceException">Unable to copy PEB; The 32-bit and 64-bit pointers are both null.</exception>
    /// <exception cref="NTStatusException">NtWow64ReadVirtualMemory failed to copy 64-bit PEB from target process; (native error message)</exception>
    /// <exception cref="Exception">ReadProcessMemory failed; (native error message)</exception>
    internal unsafe ProcessEnvironmentBlock GetPEB(SafeProcessHandle hProcess)
    {
        if (PebBaseAddress is (null, null))
            throw new NullReferenceException("Unable to copy PEB; The 32-bit and 64-bit pointers are both null.");

        using SafeBuffer<PEB64> buffer = new(numElements: 2); // We only use the type for allocation length. It's large enough for either PEB64 or PEB32.

        if (!Environment.Is64BitProcess && PebBaseAddress.w64 is not null)
        {
            ulong bytesRead64 = 0;
            NTSTATUS status;

            if ((status = PInvoke.NtWow64ReadVirtualMemory64(hProcess, (UIntPtr64)PebBaseAddress.w64, (void*)buffer.DangerousGetHandle(), buffer.ByteLength, &bytesRead64)).Code is Code.STATUS_PARTIAL_COPY)
                throw new AccessViolationException("NtWow64ReadVirtualMemory64 failed; The memory region is protected and Read access to the memory region was denied.", new NTStatusException(status));
            else if (status.Code is not Code.STATUS_SUCCESS)
                throw new NTStatusException(status, "NtWow64ReadVirtualMemory failed to copy 64-bit PEB from target process; " + status.Message);
            else
                return ProcessEnvironmentBlock = new ProcessEnvironmentBlock(buffer.Read<PEB64>(0));
        }
        else
        {
            nuint bytesRead = 0;
            if (PebBaseAddress.w32 is not null && PInvoke.ReadProcessMemory(hProcess, (void*)PebBaseAddress.w32, (void*)buffer.DangerousGetHandle(), (nuint)buffer.ByteLength, &bytesRead))
            {
                return ProcessEnvironmentBlock = new(buffer.Read<PEB32>(0));
            }
            else if (PebBaseAddress.w64 is not null && PInvoke.ReadProcessMemory(hProcess, (void*)PebBaseAddress.w64, (void*)buffer.DangerousGetHandle(), (nuint)buffer.ByteLength, &bytesRead))
            {
                return ProcessEnvironmentBlock = new(buffer.Read<PEB64>(0));
            }
            else
            {
                Win32ErrorCode err = (Win32ErrorCode)Marshal.GetLastPInvokeError();
                if (err is Win32ErrorCode.ERROR_PARTIAL_COPY)
                    throw new AccessViolationException("ReadProcessMemory failed; The memory region is protected and Read access to the memory region was denied.", new Win32Exception(err));
                else
                    throw new Exception("ReadProcessMemory failed; " + err.GetMessage(), new Win32Exception(err));
            }
        }
    }
}
