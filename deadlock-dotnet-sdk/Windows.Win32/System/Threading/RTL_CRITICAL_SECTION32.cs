namespace Windows.Win32.System.Threading
{
    internal readonly struct RTL_CRITICAL_SECTION32
    {
#pragma warning disable CS0649
        internal readonly unsafe UIntPtr32<RTL_CRITICAL_SECTION_DEBUG> DebugInfo;
        internal readonly int LockCount;
        internal readonly int RecursionCount;
        internal readonly Foundation.HANDLE32 OwningThread;
        internal readonly Foundation.HANDLE32 LockSemaphore;
        internal readonly uint SpinCount;
#pragma warning restore CS0649
    }
}
