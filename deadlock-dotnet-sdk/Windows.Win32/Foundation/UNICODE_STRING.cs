/// This file supplements code generated by CsWin32
using System.Runtime.InteropServices;

namespace Windows.Win32.Foundation;

partial struct UNICODE_STRING : IDisposable
{
    public void Dispose()
    {
        Buffer.Dispose();
    }

    /// <summary>
    /// Allocates a managed string and copies a specified number of characters from an unmanaged Unicode string into it.
    /// </summary>
    public unsafe string ToStringLength() => Marshal.PtrToStringUni((IntPtr)Buffer.Value, Length / 2);
    public string? ToStringZ() => Buffer.ToString();
    public static explicit operator string(UNICODE_STRING v) => v.ToStringLength();
}
