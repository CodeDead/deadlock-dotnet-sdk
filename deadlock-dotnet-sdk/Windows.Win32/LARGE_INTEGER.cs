using System.Runtime.InteropServices;

namespace Windows.Win32;

[StructLayout(LayoutKind.Explicit)]
internal struct LARGE_INTEGER
{
    [FieldOffset(0x00)] internal uint LowPart;
    [FieldOffset(0x04)] internal int HighPart;
    [FieldOffset(0x00)] internal long QuadPart;

}
