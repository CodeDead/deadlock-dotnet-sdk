namespace Windows.Win32;

/// <summary>
/// A stand-in for 64-bit pointers in a 32-bit runtime.
/// </summary>
public struct UIntPtr64
{
    public ulong Value;

    public static implicit operator UIntPtr64(ulong v) => new() { Value = v };
    public static implicit operator ulong(UIntPtr64 v) => v.Value;
}
