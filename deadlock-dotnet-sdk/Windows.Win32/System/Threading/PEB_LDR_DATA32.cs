using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;
using Windows.Win32.System.WindowsProgramming;

namespace Windows.Win32.System.Threading;

/// <summary>
/// https://web.archive.org/web/https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal readonly struct PEB_LDR_DATA32
{
    [FieldOffset(0x00)] internal readonly uint Length;
    [FieldOffset(0x04)] internal readonly BOOLEAN Initialized;
    [FieldOffset(0x08)] internal readonly UIntPtr32 SsHandle;
    /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they were loaded. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY32"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
    [FieldOffset(0x0C)] internal readonly LIST_ENTRY32 InLoadOrderModuleList;
    /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they appear in memory. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
    [FieldOffset(0x14)] internal readonly LIST_ENTRY32 InMemoryOrderModuleList;
    /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they were initialized. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
    [FieldOffset(0x1C)] internal readonly LIST_ENTRY32 InInitializationOrderModuleList;
    /// <summary>5.1 and higher</summary>
    [FieldOffset(0x24)] internal readonly UIntPtr32 EntryInProgress;
    /// <summary>late 6.0 and higher</summary>
    [FieldOffset(0x28)] internal readonly BOOLEAN ShutdownInProgress;
    /// <summary>late 6.0 and higher</summary>
    [FieldOffset(0x2C)] internal readonly HANDLE32 ShutdownThreadId;
}
