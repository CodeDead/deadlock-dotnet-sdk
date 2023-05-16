namespace Windows.Win32
{
    public struct SIZE_T
    {
        private nuint value;

        public static implicit operator SIZE_T(nuint v) => new() { value = v };
        public static implicit operator nuint(SIZE_T v) => v.value;

        public static explicit operator SIZE_T(nint v) => new() { value = (nuint)v };
        public static explicit operator nint(SIZE_T v) => (nint)v.value;

        public static explicit operator SIZE_T(long v) => new() { value = (nuint)v };
        public static explicit operator long(SIZE_T v) => (long)v.value;

        public static explicit operator SIZE_T(int v) => new() { value = (nuint)v };
        public static explicit operator int(SIZE_T v) => (int)v.value;
    }
}
