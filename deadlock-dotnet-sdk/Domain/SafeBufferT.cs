using System.Runtime.InteropServices;

namespace deadlock_dotnet_sdk.Domain;

public class SafeBuffer<T> : SafeBuffer
{
    public SafeBuffer(bool ownsHandle) : base(ownsHandle)
    {
    }

    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(handle);
        return true;
    }
}
