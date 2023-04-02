namespace Windows.Win32;
/// <summary>
/// https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess#PS_PROTECTION
/// </summary>
public struct PS_PROTECTION
{
    public byte Level;
    public PS_PROTECTED_TYPE Type => (PS_PROTECTED_TYPE)((Level >> 0) & 0b111);
    /// <summary>Reserved</summary>
    public byte Audit => (byte)((Level >> 3) & 0b1);
    public PS_PROTECTED_SIGNER Signer => (PS_PROTECTED_SIGNER)((Level >> 4) & 0b1111);

    public enum PS_PROTECTED_TYPE
    {
        PsProtectedTypeNone = 0,
        PsProtectedTypeProtectedLight = 1,
        PsProtectedTypeProtected = 2
    }

    public enum PS_PROTECTED_SIGNER
    {
        PsProtectedSignerNone = 0,
        PsProtectedSignerAuthenticode,
        PsProtectedSignerCodeGen,
        PsProtectedSignerAntimalware,
        PsProtectedSignerLsa,
        PsProtectedSignerWindows,
        PsProtectedSignerWinTcb,
        PsProtectedSignerWinSystem,
        PsProtectedSignerApp,
        PsProtectedSignerMax
    }
}
