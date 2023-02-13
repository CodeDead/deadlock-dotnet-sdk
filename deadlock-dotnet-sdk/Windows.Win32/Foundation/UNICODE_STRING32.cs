using System.Runtime.InteropServices;

namespace Windows.Win32.Foundation;

/// <summary>
/// The UNICODE_STRING structure is used to define Unicode strings.
/// </summary>
/// <remarks>
/// <para>The UNICODE_STRING structure is used to pass Unicode strings. Use RtlUnicodeStringInit or RtlUnicodeStringInitEx to initialize a UNICODE_STRING structure.</para>
/// <para>If the string is null-terminated, Length does not include the trailing null character.</para>
/// <para>The MaximumLength is used to indicate the length of Buffer so that if the string is passed to a conversion routine such as RtlAnsiStringToUnicodeString the returned string does not exceed the buffer size.</para>
/// </remarks>
[StructLayout(LayoutKind.Sequential, Size = 0x08)]
internal struct UNICODE_STRING32
{
    public ushort Length;
    public ushort MaximumLength;
    public UIntPtr32<char> Buffer;
}
