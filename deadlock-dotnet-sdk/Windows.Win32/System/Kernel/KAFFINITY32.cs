namespace Windows.Win32.System.Kernel;

internal struct KAFFINITY32
{
    public uint Value;

    public static implicit operator uint(KAFFINITY32 v) => v.Value;
}
