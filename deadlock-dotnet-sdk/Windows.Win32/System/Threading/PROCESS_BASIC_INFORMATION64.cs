using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;

namespace Windows.Win32.System.Threading;

/// <inheritdoc cref="PROCESS_BASIC_INFORMATION"/>
/// <remarks>64-bit struct for interop with 64-bit processes from a 32-bit process<br/>
/// When running a 64-bit process or when interacting with other 32-bit processes, use <see cref="PROCESS_BASIC_INFORMATION"/></remarks>
[StructLayout(LayoutKind.Explicit)]
internal readonly struct PROCESS_BASIC_INFORMATION64
{
    [FieldOffset(0x00)] public readonly NTSTATUS ExitStatus;
    [FieldOffset(0x04)] public readonly UIntPtr64<PEB64> PebBaseAddress;
    [FieldOffset(0x0C)] public readonly KAFFINITY64 AffinityMask;
    [FieldOffset(0x14)] public readonly KPRIORITY BasePriority;
    [FieldOffset(0x18)] public readonly ulong UniqueProcessId;
    [FieldOffset(0x20)] public readonly ulong InheritedFromUniqueProcessId;
}
