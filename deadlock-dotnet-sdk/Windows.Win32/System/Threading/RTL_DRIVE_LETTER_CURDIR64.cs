using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace Windows.Win32.System.Threading;

internal partial struct RTL_USER_PROCESS_PARAMETERS64
{
    /// <summary>
    /// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/rtl_drive_letter_curdir.htm
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = 0x18)]
    internal struct RTL_DRIVE_LETTER_CURDIR64
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING64 DosPath;

        [StructLayout(LayoutKind.Sequential)]
        public struct STRING64
        {
            public ushort Length;
            public ushort MaximumLength;
            /* The compiler adds 6 bytes of padding here, hence the total size of 24 bytes instead of 18 bytes */
            private UIntPtr64 _buffer;

            /// <summary>
            /// Copy the 8-bit string to a managed, utf-16 string
            /// </summary>
            /// <param name="processId">The ID of the process that allocated the string. After opening a handle to the process with PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ rights, a managed copy of the unmanaged string will be made in this process.</param>
            public string ToString(uint processId)
            {
                SafeProcessHandle hProcess;
                return (hProcess = PInvoke.OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ, false, processId)
                        ).IsInvalid
                    ? throw new Win32Exception()
                    : ToString(hProcess);
            }

            /// <summary>
            /// Copy the 8-bit string to a managed, utf-16 string
            /// </summary>
            /// <param name="hProcess">a SafeProcessHandle with PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ rights.</param>
            /// <returns>A managed string that holds a copy of the native string/returns>
            /// <exception cref="NTStatusException">NtWow64ReadVirtualMemory64 failed</exception>
            public unsafe string ToString(SafeProcessHandle hProcess)
            {
                // because this process uses 32-bit pointers and the target process
                // uses 64-bit pointers, we have to use a ulong to ensure the
                // pointer parameter is not truncated.
                // our buffer can be a 32-bit pointer, however.
                IntPtr buffer = Marshal.AllocHGlobal(MaximumLength);
                ulong retLength;
                Foundation.NTSTATUS status;

                return !(status = PInvoke.NtWow64ReadVirtualMemory64(hProcess, _buffer, (void*)buffer, MaximumLength, &retLength)).IsSuccessful
                    ? throw new NTStatusException(status)
                    : Marshal.PtrToStringAnsi(buffer, MaximumLength);
            }
        }
    }
}
