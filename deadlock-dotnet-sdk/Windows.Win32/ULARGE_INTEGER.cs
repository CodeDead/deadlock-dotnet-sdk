using System.Runtime.InteropServices;

namespace Windows.Win32;

[StructLayout(LayoutKind.Explicit)]
internal struct ULARGE_INTEGER
{
    [FieldOffset(0x00)] internal uint LowPart;
    [FieldOffset(0x04)] internal uint HighPart;
    [FieldOffset(0x00)] internal ulong QuadPart;

}
