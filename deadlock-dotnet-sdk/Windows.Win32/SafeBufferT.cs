using System.Runtime.InteropServices;

namespace Windows.Win32;
/// <summary>
/// https://sourcegraph.com/github.com/dotnet/runtime@main/-/blob/src/libraries/System.Private.CoreLib/src/System/Runtime/InteropServices/SafeBuffer.cs
/// </summary>
/// <typeparam name="T"></typeparam>
public class SafeBuffer<T> : SafeBuffer where T : unmanaged
{
    public SafeBuffer(nuint numBytes) : base(true)
    {
        Initialize(numBytes);
        handle = Marshal.AllocHGlobal((nint)numBytes);
    }

    public SafeBuffer(uint numElements) : base(true)
    {
        Initialize<T>(numElements);
        handle = Marshal.AllocHGlobal((nint)ByteLength);
    }

    /// <summary>
    /// heck
    /// </summary>
    /// <param name="numBytes"></param>
    /// <exception cref="OutOfMemoryException">There is insufficient memory to satisfy the request -or- the call to native function LocalReAlloc failed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">numBytes is less than zero. -or- numBytes is greater than the available address space.</exception>
    public unsafe void Reallocate(nuint numBytes)
    {
        try
        {
            handle = Marshal.ReAllocHGlobal(handle, (nint)numBytes);
            Initialize(numBytes);
        }
        catch (OutOfMemoryException)
        { throw; }
        catch (ArgumentOutOfRangeException)
        { throw; }
    }

    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(handle);
        return true;
    }
}
