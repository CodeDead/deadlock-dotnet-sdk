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

public struct UIntPtr32<T> where T : unmanaged
{
    public uint Value;

    public static implicit operator UIntPtr32<T>(uint v) => new() { Value = v };
    public static implicit operator uint(UIntPtr32<T> v) => v.Value;

    public static explicit operator UIntPtr32(UIntPtr32<T> v) => v.Value;
    public unsafe static explicit operator T*(UIntPtr32<T> v) => (T*)v.Value;
}
