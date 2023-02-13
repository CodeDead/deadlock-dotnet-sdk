namespace Windows.Win32.Foundation;

internal struct HANDLE64
{
    internal readonly UIntPtr64 Value { get; init; }

    public static explicit operator HANDLE64(UIntPtr64 v) => new() { Value = v };
    public static implicit operator UIntPtr64(HANDLE64 v) => v.Value;
}

internal struct HANDLE64<T> where T : unmanaged
{
    internal readonly UIntPtr64<T> Value { get; init; }

    public static explicit operator HANDLE64<T>(UIntPtr64<T> v) => new() { Value = v };
    public static implicit operator UIntPtr64<T>(HANDLE64<T> v) => v.Value;
}
