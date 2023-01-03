using Windows.Win32.Foundation;
using ACCESS_MASK = PInvoke.Kernel32.ACCESS_MASK;

namespace Windows.Win32;
internal struct OBJECT_TYPE_INFORMATION
{
#pragma warning disable CS0649

    public UNICODE_STRING TypeName;
    public string TypeNameAsString => TypeName.ToStringLength();
    public uint TotalNumberOfObjects;
    public uint TotalNumberOfHandles;
    public uint TotalPagedPoolUsage;
    public uint TotalNonPagedPoolUsage;
    public uint TotalNamePoolUsage;
    public uint TotalHandleTableUsage;
    public uint HighWaterNumberOfObjects;
    public uint HighWaterNumberOfHandles;
    public uint HighWaterPagedPoolUsage;
    public uint HighWaterNonPagedPoolUsage;
    public uint HighWaterNamePoolUsage;
    public uint HighWaterHandleTableUsage;
    public uint InvalidAttributes;
    public GENERIC_MAPPING GenericMapping;
    public ACCESS_MASK ValidAccessMask;
    public BOOLEAN SecurityRequired;
    public BOOLEAN MaintainHandleCount;
    public byte TypeIndex; // since WINBLUE
    public sbyte ReservedByte;
    public uint PoolType;
    public uint DefaultPagedPoolCharge;
    public uint DefaultNonPagedPoolCharge;

    public ObjectTypeInformation ToManaged() => new(this);
}

public struct ObjectTypeInformation
{
    internal ObjectTypeInformation(OBJECT_TYPE_INFORMATION oti)
    {
        TypeName = oti.TypeName.ToStringLength();

        TotalNumberOfObjects = oti.TotalNumberOfObjects;
        TotalNumberOfHandles = oti.TotalNumberOfHandles;
        TotalPagedPoolUsage = oti.TotalPagedPoolUsage;
        TotalNonPagedPoolUsage = oti.TotalNonPagedPoolUsage;
        TotalNamePoolUsage = oti.TotalNamePoolUsage;
        TotalHandleTableUsage = oti.TotalHandleTableUsage;

        HighWaterHandleTableUsage = oti.HighWaterHandleTableUsage;
        HighWaterNumberOfObjects = oti.HighWaterNumberOfObjects;
        HighWaterNumberOfHandles = oti.HighWaterNumberOfHandles;
        HighWaterPagedPoolUsage = oti.HighWaterPagedPoolUsage;
        HighWaterNonPagedPoolUsage = oti.HighWaterNonPagedPoolUsage;
        HighWaterNamePoolUsage = oti.HighWaterNamePoolUsage;
        HighWaterHandleTableUsage = oti.HighWaterHandleTableUsage;

        InvalidAttributes = oti.InvalidAttributes;
        GenericMapping = oti.GenericMapping;
        ValidAccessMask = oti.ValidAccessMask;
        SecurityRequired = oti.SecurityRequired;
        MaintainHandleCount = oti.MaintainHandleCount;
        TypeIndex = oti.TypeIndex;
        PoolType = oti.PoolType;
        DefaultPagedPoolCharge = oti.DefaultPagedPoolCharge;
        DefaultNonPagedPoolCharge = oti.DefaultNonPagedPoolCharge;
    }
    public string TypeName;
    #region Total
    public uint TotalNumberOfObjects;
    public uint TotalNumberOfHandles;
    public uint TotalPagedPoolUsage;
    public uint TotalNonPagedPoolUsage;
    public uint TotalNamePoolUsage;
    public uint TotalHandleTableUsage;
    #endregion Total
    #region HighWater
    public uint HighWaterNumberOfObjects;
    public uint HighWaterNumberOfHandles;
    public uint HighWaterPagedPoolUsage;
    public uint HighWaterNonPagedPoolUsage;
    public uint HighWaterNamePoolUsage;
    public uint HighWaterHandleTableUsage;
    #endregion HighWater
    public uint InvalidAttributes;
    public GENERIC_MAPPING GenericMapping;
    public ACCESS_MASK ValidAccessMask;
    public bool SecurityRequired;
    public bool MaintainHandleCount;
    public byte TypeIndex; // since WINBLUE
    public uint PoolType;
    public uint DefaultPagedPoolCharge;
    public uint DefaultNonPagedPoolCharge;
}
