using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;

namespace Windows.Win32.System.Threading;
/// <summary>
/// https://web.archive.org/web/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
/// <see cref="PEB"/>
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct PEB32
{
    #region INITIAL_PEB
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x00)] internal readonly BOOLEAN InheritedAddressSpace;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x01)] internal readonly BOOLEAN ReadImageFileExecOptions;
    /// <summary>
    /// Indicates whether the specified process is currently being debugged. The <b>PEB</b> structure, however, is an internal operating-system structure whose layout may change in the future. It is best to use the <a href="https://docs.microsoft.com/windows/desktop/api/debugapi/nf-debugapi-checkremotedebuggerpresent">CheckRemoteDebuggerPresent</a> function instead.<br/>
    /// Compatibility: 3.51 and higher
    /// </summary>
    [FieldOffset(0x02)] internal readonly BOOLEAN BeingDebugged;
    /// <summary>Compatibility: late 5.2 and higher</summary>
    [FieldOffset(0x03)] internal readonly PEB_BitField BitField;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x04)] internal readonly HANDLE32 Mutant;
    #endregion INITIAL_PEB

    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x08)] internal readonly UIntPtr32 ImageBaseAddress;
    /// <summary>Compatibility: all<br/>
    /// A pointer to a <a href="https://docs.microsoft.com/windows/desktop/api/winternl/ns-winternl-peb_ldr_data">PEB_LDR_DATA</a> structure that contains information about the loaded modules for the process.</summary>
    [FieldOffset(0x0C)] internal readonly unsafe UIntPtr32<PEB_LDR_DATA32> Ldr;
    /// <summary>Compatibility: All<br/>
    /// A pointer to an <a href="https://docs.microsoft.com/windows/desktop/api/winternl/ns-winternl-rtl_user_process_parameters">RTL_USER_PROCESS_PARAMETERS</a> structure that contains process parameter information such as the command line.</summary>
    [FieldOffset(0x10)] internal readonly unsafe UIntPtr32<RTL_USER_PROCESS_PARAMETERS32> ProcessParameters;
    /// <summary>Compatibility: all<br/>
    /// "SubSystem" refers to WoW64, Posix (via PSXDLL.DLL), or WSL. This stores the per-process data for the relevant subsystem.<br/></summary>
    [FieldOffset(0x14)] internal readonly UIntPtr32 SubSystemData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x18)] internal readonly UIntPtr32 ProcessHeap;

    /// <summary>Compatibility: 3.10 to 5.0</summary>
    [FieldOffset(0x1C), Obsolete] private readonly UIntPtr32 FastPebLock_obsolete;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x1C)] internal readonly UIntPtr32<RTL_CRITICAL_SECTION32> FastPebLock;
    /// <summary>Compatibility: 3.10 to 5.1</summary>
    [FieldOffset(0x20), Obsolete] private readonly UIntPtr32 FastPebLockRoutine;
    /// <summary>Compatibility: late 5.2 and higher</summary>
    [FieldOffset(0x20)] internal readonly unsafe UIntPtr32 AtlThunkSListPtr;
    /// <summary>Compatibility: 3.10 to 5.1</summary>
    [FieldOffset(0x24), Obsolete] private readonly UIntPtr32 FastPebUnlockRoutine;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x24)] internal readonly UIntPtr32 IFEOKey;

    /// <summary>Compatibility: 3.50 to 5.2</summary>
    [FieldOffset(0x28), Obsolete] private readonly uint EnvironmentUpdateCount;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x28)] internal readonly PEB_CrossProcess CrossProcessFlags;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x2C)] internal readonly UIntPtr32 KernelCallBackTable;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x2C)] internal readonly UIntPtr32 UserSharedInfoPtr;
    /// <summary>Compatibility: 3.50 to 4.0</summary>
    [FieldOffset(0x30), Obsolete] private readonly HANDLE32 EventLogSection;
    /// <summary>Compatibility: 3.50 to 4.0</summary>
    [FieldOffset(0x34), Obsolete] private readonly UIntPtr32 EventLog;
    /// <summary>Compatibility: early 5.1; early 5.2<br/>
    /// intended for checking for stack overflow</summary>
    [FieldOffset(0x34), Obsolete] private readonly uint _executionOptions;
    /// <summary>Compatibility: early 5.1; early 5.2</summary>
    [Obsolete] private uint ExecutionOptions => _executionOptions & 0b11;
    /// <summary>Compatibility: late 5.1; 6.1 and higher</summary>
    [FieldOffset(0x34)] internal readonly UIntPtr32 AtlThunkSListPtr32;

    /// <summary>Compatibility: 3.10 to early 6.0<br/>
    /// Type: PEB_FREE_BLOCK*</summary>
    [FieldOffset(0x38), Obsolete] private readonly UIntPtr32 FreeList;
    /// <summary>Compatibility: 6.1 and higher</summary>
    [FieldOffset(0x38)] internal readonly UIntPtr32 ApiSetMap;

    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x3C)] internal readonly uint TlsExpansionCounter;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x40)] internal readonly UIntPtr32 TlsBitmap;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x44)] internal unsafe fixed uint TlsBitmapBits[2];
    internal readonly unsafe uint[] TlsBitmapBits_Safe => new uint[2] { TlsBitmapBits[0], TlsBitmapBits[1] };

    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x4C)] internal readonly UIntPtr32 ReadOnlySharedMemoryBase;
    /// <summary>Compatibility: 3.10 to 5.2</summary>
    [FieldOffset(0x50), Obsolete] private readonly UIntPtr32 ReadOnlySharedMemoryHeap;
    /// <summary>Compatibility: 6.0 to 6.2</summary>
    [FieldOffset(0x50), Obsolete] private readonly UIntPtr32 HotpatchInformation;
    /// <summary>Compatibility: 1703 and higher</summary>
    [FieldOffset(0x50)] internal readonly UIntPtr32 SharedData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x54)] internal readonly UIntPtr32<UIntPtr32> ReadOnlyStaticServerData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x58)] internal readonly UIntPtr32 AnsiCodePageData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x5C)] internal readonly UIntPtr32 OemCodePageData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x60)] internal readonly UIntPtr32 UnicodeCaseTableData;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x64)] internal readonly uint NumberOfProcessors;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x68)] internal readonly uint NtGlobalFlag;
    /// <summary>Compatibility: 3.10 to 3.50</summary>
    [FieldOffset(0x68), Obsolete] private readonly long CriticalSectionTimeout_obsolete;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x70)] internal readonly long CriticalSectionTimeout;

    #region Appended for Windows NT 3.51
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x78)] internal readonly UIntPtr32 HeapSegmentReserve;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x7C)] internal readonly UIntPtr32 HeapSegmentCommit;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x80)] internal readonly UIntPtr32 HeapDeCommitTotalFreeThreshold;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x84)] internal readonly UIntPtr32 HeapDeCommitFreeBlockThreshold;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x88)] internal readonly uint NumberOfHeaps;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x8C)] internal readonly uint MaximumNumberOfHeaps;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x90)] internal readonly UIntPtr32<UIntPtr32> ProcessHeaps;
    #endregion Appended for Windows NT 3.51

    #region Appended for Windows NT 4.0
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x94)] internal readonly UIntPtr32 GdiSharedHandleTable;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x98)] internal readonly UIntPtr32 ProcessTarterHelper;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x9C)] internal readonly uint GdiDCAttributeList;
    /// <summary>Compatibility: 4.0 to 5.1</summary>
    [FieldOffset(0xA0), Obsolete] private readonly UIntPtr32 LoaderLock_obsolete;
    /// <summary>Compatibility: 5.2 and higher</summary>
    [FieldOffset(0xA0)] internal readonly UIntPtr32<RTL_CRITICAL_SECTION32> LoaderLock;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xA4)] internal readonly uint OSMajorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xA8)] internal readonly uint OSMinorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xAC)] internal readonly ushort OSBuildNumber;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xAE)] internal readonly ushort OSCSDVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xB0)] internal readonly uint OSPlatformId;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xB4)] internal readonly uint ImageSubsystem;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xB8)] internal readonly uint ImageSubsystemMajorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0xBC)] internal readonly uint ImageSubsystemMinorVersion;
    /// <summary>Compatibility: 4.0 to early 6.0</summary>
    [FieldOffset(0xC0), Obsolete] private readonly KAFFINITY32 ImageProcessAffinityMask;
    /// <summary>Compatibility: late 6.0 and higher</summary>
    [FieldOffset(0xC0)] internal readonly KAFFINITY32 ActiveProcessAffinityMask;
    /// <summary>(only 0x22 array members instead of 0x3C) Compatibility: 4.0 to early 6.0</summary>
    [FieldOffset(0xC4), Obsolete] private unsafe fixed uint GdiHandleBuffer_obsolete[0x22];
    /// <summary>4.0 and higher (x86)</summary>
    [FieldOffset(0xC4)] internal unsafe fixed uint GdiHandleBuffer[0x3C];
    internal unsafe uint[] GdiHandleBuffer_Safe
    {
        get
        {
            fixed (uint* pGdiHandleBuffer = &GdiHandleBuffer[0])
                return new ReadOnlySpan<uint>(pGdiHandleBuffer, 0x3C).ToArray();
        }
    }
    #endregion Appended for Windows NT 4.0

    #region Appended for Windows 2000
    /// <summary>Compatibility: 5.0 and higher<br/>
    /// Not supported. Type: <see cref="PPS_POST_PROCESS_INIT_ROUTINE"/></summary>
    [FieldOffset(0x014C)] internal readonly UIntPtr32 PostProcessInitRoutine;
    /// <summary>Compatibility: 5.0 and higher</summary>
    [FieldOffset(0x0150)] internal readonly UIntPtr32 TlsExpansionBitmap;
    /// <summary>Compatibility: 5.0 and higher</summary>
    [FieldOffset(0x0154)] internal unsafe fixed uint TlsExpansionBitmapBits[0x20];
    internal unsafe uint[] TlsExpansionBitmapBits_Safe
    {
        get
        {
            fixed (uint* p = &TlsExpansionBitmapBits[0])
                return new ReadOnlySpan<uint>(p, 0x20).ToArray();
        }
    }
    /// <summary>Compatibility: 5.0 and higher<br/>
    /// The Terminal Services session identifier associated with the current process.</summary>
    /// <remarks>The <see cref="SessionId"/> is one of the two <see cref="PEB"/> members that Microsoft documented when required to disclose use of internal APIs by so-called middleware.</remarks>
    [FieldOffset(0x01D4)] internal readonly uint SessionId;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x01D8)] internal readonly PEB_AppCompat AppCompatFlags;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x01E0)] internal readonly PEB_AppCompat AppCompatFlagsUser;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x01E8)] internal readonly UIntPtr32 pShimData;
    /// <summary>Compatibility: 5.0</summary>
    [FieldOffset(0x01D8), Obsolete] private readonly UIntPtr32 AppCompatInfo_NT5;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x01EC)] internal readonly UIntPtr32 AppCompatInfo;
    /// <summary>Compatibility: 5.0</summary>
    [FieldOffset(0x01DC), Obsolete] private readonly UNICODE_STRING32 CSDVersion_NT5;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x01F0)] internal readonly UNICODE_STRING32 CSDVersion;
    #endregion Appended for Windows 2000

    #region Appended for Windows XP
    /// <summary>Compatibility: 5.1 and higher<br/>
    /// Type: ACTIVATION_CONTEXT_DATA const * (pointer to a constant ACTIVATION_CONTEXT_DATA)</summary>
    [FieldOffset(0x01F8)] internal readonly UIntPtr32 ActivationContextData;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ACTIVATION_CONTEXT_DATA *</summary>
    [FieldOffset(0x01FC)] internal readonly UIntPtr32 ProcessAssemblyStorageMap;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ACTIVATION_CONTEXT_DATA const *</summary>
    [FieldOffset(0x0200)] internal readonly UIntPtr32 SystemDefaultActivationContextData;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ASSEMBLY_STORAGE_MAP *</summary>
    [FieldOffset(0x204)] internal readonly UIntPtr32 SystemAssemblyStorageMap;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x208)] internal readonly UIntPtr32 MinimumStackCommit;
    #endregion Appended for Windows XP

    #region Appended for Windows Server 2003
    /// <summary>Compatibility: 5.2 to 1809
    /// Type: FLS_CALLBACK_INFO *</summary>
    [FieldOffset(0x020C)] internal readonly UIntPtr32 FlsCallback;
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x0210)] internal readonly LIST_ENTRY32 FlatListHead; // 5.2 to 1809
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x0218)] internal readonly UIntPtr32 FlsBitmap;
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x021C)] internal unsafe fixed uint FlsBitmapBits[4];
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x022C)] internal readonly uint FlsHighIndex;
    #endregion Appended for Windows Server 2003

    #region Appended for Windows Vista
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x0230)] internal readonly UIntPtr32 WerRegistrationData;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x0234)] internal readonly UIntPtr32 WerShipAssertPtr;
    #endregion Appended for Windows Vista

    #region Appended for Windows 7
    /// <summary>Compatibility: 6.1 only</summary>
    [FieldOffset(0x0238)] internal readonly UIntPtr32 pContextData;
    /* [FieldOffset(0x0238)] internal readonly UIntPtr32 pUnused; */
    /// <summary>Compatibility: 6.1 and higher</summary>
    [FieldOffset(0x023C)] internal readonly UIntPtr32 pImageHeaderHash;
    [FieldOffset(0x0240)] internal readonly PEB_Tracing TracingFlags;
    #endregion Appended for Windows 7

    #region Appended for Windows 8
    /// <summary>Compatibility: 6.2 and higher</summary>
    [FieldOffset(0x0248)] internal readonly ulong CsrServerReadOnlySharedMemoryBase;
    #endregion Appended for Windows 8

    #region Appended Later in Windows 10
    /// <summary>Compatibility: 1511 and higher</summary>
    [FieldOffset(0x0250)] internal readonly uint TppWorkerpListLock;
    /// <summary>Compatibility: 1511 and higher</summary>
    [FieldOffset(0x0254)] internal readonly LIST_ENTRY32 TppWorkerList;
    /// <summary>Compatibility: 1511 and higher<br/>
    /// Type: Fixed Array of void*</summary>
    [FieldOffset(0x025C)] internal unsafe fixed uint WaitOnAddressHashTable[0x80];
    /// <summary>Compatibility: 1709 and higher</summary>
    [FieldOffset(0x045C)] internal readonly UIntPtr32 TelemetryCoverageHeader;
    /// <summary>Compatibility: 1709 and higher</summary>
    [FieldOffset(0x0460)] internal readonly uint CloudFileFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    [FieldOffset(0x0464)] internal readonly uint CloudFileDiagFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    [FieldOffset(0x0468)] internal readonly byte PlaceholderCompatibilityMode;
    /// <summary>Compatibility: 1803 and higher
    /// Type: LEAP_SECOND_DATA *</summary>
    [FieldOffset(0x0470)] internal readonly UIntPtr32 LeapSecondData;
    [FieldOffset(0x0474)] internal readonly PEB_LeapSecond LeapSecondFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    /// <remarks>The <see cref="NtGlobalFlag2"/> member is indeed named for being in some sense an extension of the much older <see cref="NtGlobalFlag"/>.
    ///     Each corresponds to a registry value that can be in either or both of two well-known keys.
    ///     Each also is the name of a variable in the kernel (one exported, the other only internal), which the kernel initializes from the corresponding registry value in the <c>Session Manager</c> key.
    ///     This then provides the initial value for the corresponding <see cref="PEB"/> member, which may then be re-initialized from the same-named registry value in the program's subkey of the <c>Image File Execution Options</c>.<br/><br/>
    /// Only one flag in the new set of them is yet known to be defined.
    ///     A set 0x00000001 bit in the data for the <c>GlobalFlag2</c> registry value becomes a set 0x00000001 bit in the <see cref="NtGlobalFlag2"/> member.
    ///     From there it may set the <see cref="PEB_LeapSecond.SixtySecondEnabled"/> bit in union with the <see cref="LeapSecondFlags"/>.
    ///     The intended effect is that the newly exported <c>RtlpTimeFieldsToTime</c> and <c>RtlpTimeToTimeFields</c> functions become leap-second-aware: when <see cref="LeapSecondData"/> is available, these functions accommodate 60 as the seconds field in a time.<br/><br/>
    /// This support for leap seconds was all new for the 1809 release and thus was also still new, roughly, for the article <see href="https://techcommunity.microsoft.com/t5/networking/blog/leap-seconds-for-the-it-pro-what-you-need-to-know/ba-p/339811">Leap Seconds for the IT Pro: What you need to know</see> at a Microsoft blog dated Feb 14 2019.
    ///     Years later, on 27th January 2023, this is still the only match that Google finds when asked to search microsoft.com for pages that contain <c>GlobalFlag2</c>.
    ///     This is a good example of a trend in what passes as documentation.
    ///     At various levels of Windows administration and programming, it is often that Microsoft's only disclosure of some new feature, large or small, is a blog.
    ///     Administrators and programmers are inevitably grateful that Microsoft employees take the time to blog.
    ///     But let's please not overlook that these blogs are not documentation.
    ///     The helpfulness of Microsoft's employees in explaining new features in fast-moving development, and the readiness of occasionally desperate administrators and programmers to latch on to this help, disguises that Microsoft is systematically skipping the work of documenting these features.</remarks>
    [FieldOffset(0x0478)] internal readonly uint NtGlobalFlag2;
    #endregion Appended Later in Windows 10
}
