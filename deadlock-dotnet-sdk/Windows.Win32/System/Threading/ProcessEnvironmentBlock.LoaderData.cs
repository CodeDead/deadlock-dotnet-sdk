using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;

namespace Windows.Win32.System.Threading;

public partial class ProcessEnvironmentBlock
{
    public class LoaderData
    {
        public LoaderData(PEB_LDR_DATA32 loaderData32)
        {
            EntryInProgress.w32 = loaderData32.EntryInProgress;
            InInitializationOrderModuleList.w32 = loaderData32.InInitializationOrderModuleList;
            Initialized = loaderData32.Initialized;
            InLoadOrderModuleList.w32 = loaderData32.InLoadOrderModuleList;
            InMemoryOrderModuleList.w32 = loaderData32.InMemoryOrderModuleList;
            Length = loaderData32.Length;
            ShutdownInProgress = loaderData32.ShutdownInProgress;
            SsHandle.w32 = loaderData32.SsHandle;
        }

        public LoaderData(PEB_LDR_DATA64 loaderData64)
        {
            EntryInProgress.w64 = loaderData64.EntryInProgress;
            InInitializationOrderModuleList.w64 = loaderData64.InInitializationOrderModuleList;
            Initialized = loaderData64.Initialized;
            InLoadOrderModuleList.w64 = loaderData64.InLoadOrderModuleList;
            InMemoryOrderModuleList.w64 = loaderData64.InMemoryOrderModuleList;
            Length = loaderData64.Length;
            ShutdownInProgress = loaderData64.ShutdownInProgress;
            SsHandle.w64 = loaderData64.SsHandle;
        }

        public uint Length;
        public BOOLEAN Initialized;
        public (UIntPtr32? w32, UIntPtr64? w64) SsHandle;
        /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they were loaded. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
        public (LIST_ENTRY32? w32, LIST_ENTRY64? w64) InLoadOrderModuleList;
        /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they appear in memory. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
        public (LIST_ENTRY32? w32, LIST_ENTRY64? w64) InMemoryOrderModuleList;
        /// <summary>The head of a doubly-linked list that contains the loaded modules for the process in the order they were initialized. Each item in the list is a pointer to an <see cref="LDR_DATA_TABLE_ENTRY64"/> structure. See <see href="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists#doubly-linked-lists">Double Linked Lists</see></summary>
        public (LIST_ENTRY32? w32, LIST_ENTRY64? w64) InInitializationOrderModuleList;
        public (UIntPtr32? w32, UIntPtr64? w64) EntryInProgress; // 5.1 and higher
        public BOOLEAN ShutdownInProgress; // late 6.0 and higher
        public (HANDLE32? w32, HANDLE64? w64) ShutdownThreadId; // late 6.0 and higher
    }
}
