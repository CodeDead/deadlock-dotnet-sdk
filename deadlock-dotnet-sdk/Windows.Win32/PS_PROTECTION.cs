namespace Windows.Win32;
/// <summary>
/// https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess#PS_PROTECTION
/// </summary>
internal struct PS_PROTECTION
{
    public byte Level;
    public byte Type => (byte)((Level >> 0) & 0b111);
    public byte Audit => (byte)((Level >> 3) & 0b1); // Reserved
    public byte Signer => (byte)((Level >> 4) & 0b1111);
}
