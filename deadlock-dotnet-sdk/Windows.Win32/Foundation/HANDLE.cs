/// This file supplements code generated by CsWin32
using Win32Exception = System.ComponentModel.Win32Exception;

namespace Windows.Win32.Foundation;

partial struct HANDLE : IComparable<HANDLE>
{
    public static implicit operator HANDLE(nuint v) => new((nint)v);
    public static implicit operator nuint(HANDLE v) => (nuint)(nint)v.Value;

    public static implicit operator HANDLE(nint v) => new(v);
    public static implicit operator nint(HANDLE v) => v.Value;

    /// <summary>
    /// Close the handle via the CloseHandle function
    /// </summary>
    /// <exception cref="Win32Exception">
    /// If the application is running under a debugger, the function will throw an
    /// exception if it receives either a handle value that is not valid or a
    /// pseudo-handle value. This can happen if you close a handle twice, or if you
    /// call CloseHandle on a handle returned by the FindFirstFile function instead
    /// of calling the FindClose function.
    /// </exception>
    public void Close()
    {
        if (!PInvoke.CloseHandle(this))
            throw new Win32Exception();
    }

    public int CompareTo(HANDLE other) => Value.CompareTo(other);
}
