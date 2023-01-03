using Microsoft.VisualBasic;

namespace Windows.Win32;
struct OBJECT_TYPES_INFORMATION : IEquatable<OBJECT_TYPES_INFORMATION>
{
    public uint NumberOfTypes = 0;

    public OBJECT_TYPES_INFORMATION(uint numberOfTypes)
    {
        NumberOfTypes = numberOfTypes;
    }

    public static explicit operator uint(OBJECT_TYPES_INFORMATION v) => v.NumberOfTypes;

    public static bool operator ==(OBJECT_TYPES_INFORMATION x, OBJECT_TYPES_INFORMATION y) => x.NumberOfTypes == y.NumberOfTypes;

    public static bool operator !=(OBJECT_TYPES_INFORMATION x, OBJECT_TYPES_INFORMATION y) => x.NumberOfTypes != y.NumberOfTypes;

    public override bool Equals(object? obj)
    {
        return obj is OBJECT_TYPES_INFORMATION information &&
               NumberOfTypes == information.NumberOfTypes;
    }

    public bool Equals(OBJECT_TYPES_INFORMATION other) => NumberOfTypes == other.NumberOfTypes;
}
