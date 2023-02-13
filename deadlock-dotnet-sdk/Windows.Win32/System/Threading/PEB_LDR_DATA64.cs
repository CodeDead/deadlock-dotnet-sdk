using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;
using Windows.Win32.System.WindowsProgramming;

namespace Windows.Win32.System.Threading;

/// <summary>
/// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct PEB_LDR_DATA64
{
    [FieldOffset(0x00)] internal readonly uint Length;
    [FieldOffset(0x04)] internal readonly BOOLEAN Initialized;
    [FieldOffset(0x08)] internal readonly unsafe UIntPtr64 SsHandle;
    [FieldOffset(0x10)] internal readonly LIST_ENTRY64<LDR_DATA_TABLE_ENTRY64> InLoadOrderModuleList;
    /// <summary>The head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an <b>LDR_DATA_TABLE_ENTRY</b> structure. For more information, see Remarks.</summary>
    [FieldOffset(0x20)] internal readonly LIST_ENTRY64<LDR_DATA_TABLE_ENTRY64> InMemoryOrderModuleList;
    [FieldOffset(0x30)] internal readonly LIST_ENTRY64<LDR_DATA_TABLE_ENTRY64> InInitializationOrderModuleList;
    [FieldOffset(0x40)] internal readonly unsafe UIntPtr64 EntryInProgress; // 5.1 and higher
    [FieldOffset(0x48)] internal readonly BOOLEAN ShutdownInProgress; // late 6.0 and higher
    [FieldOffset(0x50)] internal readonly HANDLE64 ShutdownThreadId; // late 6.0 and higher
}
