using System.Runtime.InteropServices;

namespace Windows.Win32.Foundation;

[StructLayout(LayoutKind.Sequential, Size = 0x10)]
public struct UNICODE_STRING64
{
    public ushort Length;
    public ushort MaximumLength;
    public UIntPtr64<char> Buffer;
}
