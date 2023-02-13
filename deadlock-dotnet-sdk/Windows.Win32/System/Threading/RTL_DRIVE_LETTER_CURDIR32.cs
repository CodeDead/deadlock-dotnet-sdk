using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace Windows.Win32.System.Threading;

internal partial struct RTL_USER_PROCESS_PARAMETERS32
{
    /// <summary>
    /// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/rtl_drive_letter_curdir.htm
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = 0x10)]
    public struct RTL_DRIVE_LETTER_CURDIR32
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING32 DosPath;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct STRING32
        {
            public ushort Length;
            public ushort MaximumLength;
            public readonly UIntPtr32<byte> _buffer;

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
            /// <exception cref="NTStatusException">ReadProcessMemory failed</exception>
            public unsafe string ToString(SafeProcessHandle hProcess)
            {
                IntPtr buffer = Marshal.AllocHGlobal(MaximumLength);
                nuint retLength;

                return !PInvoke.ReadProcessMemory(hProcess, (void*)_buffer, (void*)buffer, MaximumLength, &retLength)
                    ? throw new Win32Exception()
                    : Marshal.PtrToStringAnsi(buffer, MaximumLength);
            }
        }
    }
}
