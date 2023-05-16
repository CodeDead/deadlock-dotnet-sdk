namespace Windows.Win32.System.Kernel;

public struct KAFFINITY64
{
    public ulong Value;

    public static implicit operator ulong(KAFFINITY64 v) => v.Value;
}
