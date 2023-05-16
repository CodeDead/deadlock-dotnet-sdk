namespace Windows.Win32.System.WindowsProgramming;
public enum LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    /// <summary>1709 and higher</summary>
    LoadReasonEnclavePrimary,
    /// <summary>1709 and higher</summary>
    LoadReasonEnclaveDependency,
    LoadReasonUnknown = -1
}
