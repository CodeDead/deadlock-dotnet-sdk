// https://web.archive.org/web/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm

namespace Windows.Win32.System.WindowsProgramming;

/// <summary>
/// unless otherwise specified, all flags are valid for NT 6.2 and higher.
/// Flags deprecated before Windows 7 are not included in this enum
/// </summary>
[Flags]
public enum LdrEntryFlags : uint
{
    PackagedBinary = 0x1U,
    /// <summary>3.51 to 6.1 (Win7)</summary>
    LDRP_STATIC_LINK = 1 << 1,
    MarkedForRemoval = 1 << 1,
    ImageDll = 1 << 2,
    /// <summary>5.1 to 6.1 (Win7)</summary>
    LDRP_SHIMENG_ENTRY_PROCESSED = 1 << 3,
    LoadNotificationsSent = 1 << 3,
    TelemetryEntryProcessed = 1 << 4,
    ProcessStaticImport = 1 << 5,
    InLegacyLists = 1 << 6,
    InIndexes = 1 << 7,
    InExceptionTable = 1 << 8,
    LoadInProgress = 1 << 12,
    /// <summary>3.51 to 6.1 (Win7)</summary>
    LDRP_UNLOAD_IN_PROGRESS = 1 << 13,
    /// <summary>10.0 and higher</summary>
    LoadConfigProcessed = 1 << 13,
    EntryProcessed = 1 << 14,
    /// <summary>10.0 and higher</summary>
    ProtectDelayLoad = 1 << 15,
    DontCallForThreads = 1 << 18,
    ProcessAttachCalled = 1 << 19,
    ProcessAttachFailed = 1 << 20,
    CorDeferredValidate = 1 << 21,
    CorImage = 1 << 22,
    /// <summary>5.1 to 6.1 (Win7)</summary>
    LDRP_COR_OWNS_UNMAP = 1 << 23,
    DontRelocate = 1 << 23,
    CorILOnly = 1 << 24,
    /// <summary>1803 and higher</summary>
    ChpeImage = 1 << 25,
    Redirected = 1 << 28,
    CompatDatabaseProcessed = 1U << 31
}
