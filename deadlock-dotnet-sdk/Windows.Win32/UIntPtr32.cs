namespace Windows.Win32;

/// <summary>
/// A stand-in for 32-bit pointers in a 64-bit runtime.
/// </summary>
public struct UIntPtr32
{
    public uint Value;

    public static implicit operator UIntPtr32(uint v) => new() { Value = v };
    public static implicit operator uint(UIntPtr32 v) => v.Value;

    public unsafe static explicit operator void*(UIntPtr32 v) => (void*)v.Value;
}
