namespace Windows.Win32.System.Threading
{
    public readonly struct RTL_CRITICAL_SECTION32
    {
#pragma warning disable CS0649
        public readonly unsafe UIntPtr32<RTL_CRITICAL_SECTION_DEBUG> DebugInfo;
        public readonly int LockCount;
        public readonly int RecursionCount;
        public readonly Foundation.HANDLE32 OwningThread;
        public readonly Foundation.HANDLE32 LockSemaphore;
        public readonly uint SpinCount;
#pragma warning restore CS0649
    }
}
