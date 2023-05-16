namespace Windows.Win32.System.Threading;

/// <summary>
/// https://web.archive.org/web/20221204112657/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/crossprocessflags.htm
/// </summary>
[Flags]
public enum PEB_CrossProcess : uint
{
    /// <summary>Compatibility: 6.0 and higher</summary>
    ProcessInJob = 1,
    /// <summary>Compatibility: 6.0 and higher</summary>
    ProcessInitializing = 1 << 1,
    /// <summary>Compatibility: 6.1 and higher</summary>
    ProcessUsingVEH = 1 << 2,
    /// <summary>Compatibility: 6.1 and higher</summary>
    ProcessUsingVCH = 1 << 3,
    /// <summary>Compatibility: 6.1 and higher</summary>
    ProcessUsingFTH = 1 << 4,
    /// <summary>Compatibility: 1703 and higher</summary>
    ProcessPreviouslyThrottled = 1 << 5,
    /// <summary>Compatibility: 1703 and higher</summary>
    ProcessCurrentlyThrottled = 1 << 6,
    ProcessImagesHotPatched = 1 << 7,
}
