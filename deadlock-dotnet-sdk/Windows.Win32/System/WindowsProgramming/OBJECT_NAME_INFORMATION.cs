using Windows.Win32.Foundation;

namespace Windows.Win32.System.WindowsProgramming;

public struct OBJECT_NAME_INFORMATION
{
    public UNICODE_STRING Name;

    public string NameAsString => Name.ToStringLength();
}
