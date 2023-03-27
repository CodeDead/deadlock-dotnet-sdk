using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;
using Windows.Win32.System.WindowsProgramming;

namespace Windows.Win32.System.Threading;

/// <summary>https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
/// Essentially, the head of three double-linked lists of LDR_DATA_TABLE_ENTRY structures.</summary>
[StructLayout(LayoutKind.Explicit)]
internal readonly struct PEB_LDR_DATA64
{
    [FieldOffset(0x00)] internal readonly uint Length;
    [FieldOffset(0x04)] internal readonly BOOLEAN Initialized;
    [FieldOffset(0x08)] internal readonly unsafe UIntPtr64 SsHandle;
    /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they were loaded. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
    [FieldOffset(0x10)] internal readonly LIST_ENTRY64 InLoadOrderModuleList;
    /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they appear in memory. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
    [FieldOffset(0x20)] internal readonly LIST_ENTRY64 InMemoryOrderModuleList;
    /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they were initialized. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
    [FieldOffset(0x30)] internal readonly LIST_ENTRY64 InInitializationOrderModuleList;
    [FieldOffset(0x40)] internal readonly unsafe UIntPtr64 EntryInProgress; // 5.1 and higher
    [FieldOffset(0x48)] internal readonly BOOLEAN ShutdownInProgress; // late 6.0 and higher
    [FieldOffset(0x50)] internal readonly HANDLE64 ShutdownThreadId; // late 6.0 and higher
}
