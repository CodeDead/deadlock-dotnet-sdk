using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;

namespace Windows.Win32.System.Threading;

/// <inheritdoc cref="PROCESS_BASIC_INFORMATION"/>
/// <remarks>32-bit struct for interop with 32-bit processes from a 64-bit process<br/>
/// When running a 32-bit process or when interacting with other 64-bit processes, use <see cref="PROCESS_BASIC_INFORMATION"/></remarks>
[StructLayout(LayoutKind.Explicit)]
public readonly struct PROCESS_BASIC_INFORMATION32
{
    [FieldOffset(0x00)] public readonly NTSTATUS ExitStatus;
    [FieldOffset(0x04)] public readonly UIntPtr32<PEB32> PebBaseAddress;
    [FieldOffset(0x08)] public readonly KAFFINITY32 AffinityMask;
    [FieldOffset(0x0B)] public readonly KPRIORITY BasePriority;
    [FieldOffset(0x10)] public readonly uint UniqueProcessId;
    [FieldOffset(0x14)] public readonly uint InheritedFromUniqueProcessId;
}
