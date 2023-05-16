namespace Windows.Win32.System.WindowsProgramming;

/// <summary>
/// The generated enum is missing most entries and has ObjectTypeInformation as `1` instead of `2`. Will changing its value prove to be a mistake?
/// https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntobapi_x/object_information_class.htm
/// </summary>
public enum OBJECT_INFORMATION_CLASS
{
    /// <summary>
    /// A <see cref="PUBLIC_OBJECT_BASIC_INFORMATION">PUBLIC_OBJECT_BASIC_INFORMATION</see> structure is supplied.
    /// </summary>
    ObjectBasicInformation = 0,
    /// <summary>An <see cref="OBJECT_NAME_INFORMATION"/> structure is supplied.</summary>
    ObjectNameInformation = 1,
    /// <summary>A <see cref="PUBLIC_OBJECT_TYPE_INFORMATION"/> structure is supplied.</summary>
    ObjectTypeInformation = 2,
    /// <summary>3.50 and higher; A <see cref="OBJECT_TYPES_INFORMATION"/> structure is supplied.</summary>
    ObjectTypesInformation = 3,
    /// <summary>3.50 and higher</summary>
    ObjectHandleFlagInformation = 4,
    /// <summary>5.2 and higher</summary>
    ObjectSessionInformation = 5,
    /// <summary>1703 and higher</summary>
    ObjectSessionObjectInformation = 6,
    /// <summary>6.1 to 1607</summary>
    MaxObjectInfoClass_old = ObjectSessionObjectInformation,
    /// <summary>version > 1607</summary>
    MaxObjectInfoClass_new = 7
}
