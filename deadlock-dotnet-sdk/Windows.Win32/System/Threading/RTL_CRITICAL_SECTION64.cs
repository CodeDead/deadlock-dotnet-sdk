namespace Windows.Win32.System.Threading
{
    public readonly struct RTL_CRITICAL_SECTION64
    {
#pragma warning disable CS0649
        public readonly unsafe UIntPtr64<RTL_CRITICAL_SECTION_DEBUG> DebugInfo;
        public readonly int LockCount;
        public readonly int RecursionCount;
        public readonly Foundation.HANDLE64 OwningThread;
        public readonly Foundation.HANDLE64 LockSemaphore;
        public readonly ulong SpinCount;
#pragma warning restore CS0649
    }
}
