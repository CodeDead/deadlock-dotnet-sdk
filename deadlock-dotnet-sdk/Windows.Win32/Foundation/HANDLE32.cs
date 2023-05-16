namespace Windows.Win32.Foundation;

public readonly struct HANDLE32
{
    public readonly UIntPtr32 Value { get; init; }

    public static explicit operator HANDLE32(UIntPtr32 v) => new() { Value = v };
    public static implicit operator UIntPtr32(HANDLE32 v) => v.Value;
}

public readonly struct HANDLE32<T> where T : unmanaged
{
    public readonly UIntPtr32<T> Value { get; init; }

    public static explicit operator HANDLE32<T>(UIntPtr32<T> v) => new() { Value = v };
    public static implicit operator UIntPtr32<T>(HANDLE32<T> v) => v.Value;
}
