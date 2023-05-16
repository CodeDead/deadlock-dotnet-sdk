namespace Windows.Win32.System.Threading;

/// <summary>
/// This typedef is not emitted by Win32Metadata, but is defined in wdm.h of Windows SDK 10.0.22621.0
/// </summary>
public struct KPRIORITY
{
    public KPRIORITY(int value) : this() => Value = value;

    public int Value { get; set; }

    public static implicit operator KPRIORITY(int value) => new(value);
    public static explicit operator int(KPRIORITY kpriority) => kpriority.Value;
}
