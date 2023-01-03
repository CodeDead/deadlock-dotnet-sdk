/// This file supplements code generated by CsWin32
using System.Runtime.InteropServices;

namespace Windows.Win32.Foundation;

unsafe readonly partial struct PWSTR : IDisposable
{
    /// <summary>
    /// Free the PWSTR's memory with Marshal.FreeHGlobal(IntPtr)
    /// </summary>
    public void Dispose() => Marshal.FreeHGlobal((IntPtr)Value);

    public static implicit operator PWSTR(IntPtr v) => new((char*)v);
}
