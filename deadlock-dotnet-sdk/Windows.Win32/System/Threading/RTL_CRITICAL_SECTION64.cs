namespace Windows.Win32.System.Threading
{
    internal readonly struct RTL_CRITICAL_SECTION64
    {
        internal readonly unsafe UIntPtr64<RTL_CRITICAL_SECTION_DEBUG> DebugInfo;
        internal readonly int LockCount;
        internal readonly int RecursionCount;
        internal readonly Foundation.HANDLE64 OwningThread;
        internal readonly Foundation.HANDLE64 LockSemaphore;
        internal readonly ulong SpinCount;
    }
}
