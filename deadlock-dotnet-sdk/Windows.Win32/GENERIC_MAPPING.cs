using static PInvoke.Kernel32;

namespace Windows.Win32;
public struct GENERIC_MAPPING
{
    public ACCESS_MASK GenericRead;
    public ACCESS_MASK GenericWrite;
    public ACCESS_MASK GenericExecute;
    public ACCESS_MASK GenericAll;
}
