namespace Windows.Win32.System.Threading;

[Flags]
public enum PEB_BitField
{
    /// <summary>Compatibility: late 5.2 and higher</summary>
    ImageUsedLargePages = 1,
    /// <summary>Compatibility: 6.0 and higher</summary>
    IsProtectedProcess = 2,
    /// <summary>Compatibility: 6.0 to 6.2</summary>
    IsLegacyProcess = 4,
    /// <summary>Compatibility: 6.0 to 6.2</summary>
    IsImageDynamicallyRelocated_VistaToWin8 = 8,
    /// <summary>Compatibility: 6.3 and higher</summary>
    IsImageDynamicallyRelocated = 4,
    /// <summary>Compatibility: late 6.0 to 6.2</summary>
    SkipPatchingUser32Forwarders_VistaToWin8 = 16,
    /// <summary>Compatibility: 6.3 and higher</summary>
    SkipPatchingUser32Forwarders = 8,
    /// <summary>Compatibility: 6.2</summary>
    IsPackagedProcess_Win8 = 32,
    /// <summary>Compatibility: 6.3 and higher</summary>
    IsPackagedProcess = 16,
    /// <summary>Compatibility: 6.2</summary>
    IsAppContainer_Win8 = 64,
    /// <summary>Compatibility: 6.3 and higher</summary>
    IsAppContainer = 32,
    /// <summary>Compatibility: 6.3 and higher</summary>
    IsProtectedProcessLight = 128,
    /// <summary>Compatibility: 1607 and higher</summary>
    IsLongPathAwareProcess = 256,

}
