using Windows.Win32.Foundation;

namespace Windows.Win32.System.WindowsProgramming;

public struct OBJECT_NAME_INFORMATION
{
    internal UNICODE_STRING Name;

    public string NameAsString => Name.ToStringLength();
}
