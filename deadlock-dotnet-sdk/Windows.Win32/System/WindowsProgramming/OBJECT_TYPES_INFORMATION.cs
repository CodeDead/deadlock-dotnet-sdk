namespace Windows.Win32.System.WindowsProgramming;
public struct OBJECT_TYPES_INFORMATION
{
    public OBJECT_TYPES_INFORMATION(uint numberOfTypes)
    {
        NumberOfTypes = numberOfTypes;
    }

    public uint NumberOfTypes;

    public unsafe OBJECT_TYPE_INFORMATION TypeInformation_0 = default;
    public unsafe OBJECT_TYPE_INFORMATION TypeInformation_1 = default;

    public unsafe OBJECT_TYPE_INFORMATION[] TypeInformation
    {
        get
        {
            fixed (OBJECT_TYPE_INFORMATION* p = &TypeInformation_0)
                return new ReadOnlySpan<OBJECT_TYPE_INFORMATION>(p, (int)NumberOfTypes).ToArray();
        }
    }
}
