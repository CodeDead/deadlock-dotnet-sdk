using System.Diagnostics.Contracts;
namespace Windows.Win32;

/// <inheritdoc cref="UIntPtr64"/>
public struct UIntPtr64<T> where T : unmanaged
{
    public ulong Value;

    public static implicit operator UIntPtr64<T>(ulong v) => new() { Value = v };
    public static implicit operator ulong(UIntPtr64<T> v) => v.Value;

    public static explicit operator UIntPtr64(UIntPtr64<T> v) => v.Value;
    public static explicit operator UIntPtr64<T>(UIntPtr64 v) => new() { Value = v.Value };

    public unsafe static explicit operator T*(UIntPtr64<T> v) => (T*)v.Value;
}
