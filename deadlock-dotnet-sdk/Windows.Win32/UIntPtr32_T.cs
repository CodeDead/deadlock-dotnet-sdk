namespace Windows.Win32;

/// <inheritdoc cref="UIntPtr32"/>
public struct UIntPtr32<T> where T : unmanaged
{
    public uint Value;

    public static implicit operator UIntPtr32<T>(uint v) => new() { Value = v };
    public static implicit operator uint(UIntPtr32<T> v) => v.Value;

    public static explicit operator UIntPtr32(UIntPtr32<T> v) => v.Value;
    public static unsafe explicit operator T*(UIntPtr32<T> v) => (T*)v.Value;
}
