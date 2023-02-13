namespace Windows.Win32;

/// <summary>
/// A stand-in for 64-bit pointers in a 32-bit runtime.
/// </summary>
internal struct UIntPtr64
{
    public ulong Value;

    public static implicit operator UIntPtr64(ulong v) => new() { Value = v };
    public static implicit operator ulong(UIntPtr64 v) => v.Value;
}

internal struct UIntPtr64<T> where T : unmanaged
{
    public ulong Value;

    public static implicit operator UIntPtr64<T>(ulong v) => new() { Value = v };
    public static implicit operator ulong(UIntPtr64<T> v) => v.Value;

    public static explicit operator UIntPtr64(UIntPtr64<T> v) => v.Value;
}
