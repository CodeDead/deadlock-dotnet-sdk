using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;

namespace Windows.Win32.System.Threading;
/// <summary>
/// https://web.archive.org/web/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
/// <see cref="PEB"/>
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct PEB64
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
    [FieldOffset(0x08)] internal readonly HANDLE64 Mutant;
    #endregion INITIAL_PEB

    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x20)] internal readonly UIntPtr64 ImageBaseAddress;
    /// <summary>Compatibility: all<br/>
    /// A pointer to a <a href="https://docs.microsoft.com/windows/desktop/api/winternl/ns-winternl-peb_ldr_data">PEB_LDR_DATA</a> structure that contains information about the loaded modules for the process.</summary>
    [FieldOffset(0x18)] internal readonly unsafe UIntPtr64<PEB_LDR_DATA64> Ldr;
    /// <summary>Compatibility: All<br/>
    /// A pointer to an <a href="https://docs.microsoft.com/windows/desktop/api/winternl/ns-winternl-rtl_user_process_parameters">RTL_USER_PROCESS_PARAMETERS</a> structure that contains process parameter information such as the command line.</summary>
    [FieldOffset(0x20)] internal readonly unsafe UIntPtr64<RTL_USER_PROCESS_PARAMETERS64> ProcessParameters;
    /// <summary>Compatibility: all<br/>
    /// "SubSystem" refers to WoW64, Posix (via PSXDLL.DLL), or WSL. This stores the per-process data for the relevant subsystem.<br/></summary>
    [FieldOffset(0x28)] internal readonly UIntPtr64 SubSystemData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x30)] internal readonly UIntPtr64 ProcessHeap;

    /// <summary>Compatibility: 3.10 to 5.0</summary>
    [FieldOffset(0x38), Obsolete] private readonly UIntPtr64 FastPebLock_obsolete;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x38)] internal readonly UIntPtr64<RTL_CRITICAL_SECTION64> FastPebLock;
    /// <summary>Compatibility: 3.10 to 5.1</summary>
    [FieldOffset(0x40), Obsolete] private readonly UIntPtr64 FastPebLockRoutine;
    /// <summary>Compatibility: late 5.2 and higher</summary>
    [FieldOffset(0x40)] internal readonly unsafe UIntPtr64 AtlThunkSListPtr;
    /// <summary>Compatibility: 3.10 to 5.1</summary>
    [FieldOffset(0x48), Obsolete] private readonly UIntPtr64 FastPebUnlockRoutine;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x48)] internal readonly UIntPtr64 IFEOKey;

    /// <summary>Compatibility: 3.50 to 5.2</summary>
    [FieldOffset(0x50), Obsolete] private readonly uint EnvironmentUpdateCount;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x50)] internal readonly PEB_CrossProcess CrossProcessFlags;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0x58)] internal readonly UIntPtr64 KernelCallBackTable;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x58)] internal readonly UIntPtr64 UserSharedInfoPtr;
    /* NOTE: EventLogSection and EventLog became obsolete PEB before Windows 64-bit existed */
    /* NOTE: ExecutionOptions became obsolete before Windows 64-bit existed */
    /// <summary>Compatibility: late 5.1; 6.1 and higher</summary>
    [FieldOffset(0x64)] internal readonly UIntPtr64 AtlThunkSListPtr32;

    /// <summary>Compatibility: 3.10 to early 6.0<br/>
    /// Type: PEB_FREE_BLOCK*</summary>
    [FieldOffset(0x68), Obsolete] private readonly UIntPtr64 FreeList;
    /// <summary>Compatibility: 6.1 and higher</summary>
    [FieldOffset(0x68)] internal readonly UIntPtr64 ApiSetMap;

    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x70)] internal readonly uint TlsExpansionCounter;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x78)] internal readonly UIntPtr64 TlsBitmap;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x80)] internal unsafe fixed uint TlsBitmapBits[2];
    internal readonly unsafe uint[] TlsBitmapBits_Safe => new uint[2] { TlsBitmapBits[0], TlsBitmapBits[1] };

    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x88)] internal readonly UIntPtr64 ReadOnlySharedMemoryBase;
    /// <summary>Compatibility: 3.10 to 5.2</summary>
    [FieldOffset(0x90), Obsolete] private readonly UIntPtr64 ReadOnlySharedMemoryHeap;
    /// <summary>Compatibility: 6.0 to 6.2</summary>
    [FieldOffset(0x90), Obsolete] private readonly UIntPtr64 HotpatchInformation;
    /// <summary>Compatibility: 1703 and higher</summary>
    [FieldOffset(0x90)] internal readonly UIntPtr64 SharedData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0x98)] internal readonly UIntPtr64<UIntPtr64> ReadOnlyStaticServerData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0xA0)] internal readonly UIntPtr64 AnsiCodePageData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0xA8)] internal readonly UIntPtr64 OemCodePageData;
    /// <summary>Compatibility: all</summary>
    [FieldOffset(0xB0)] internal readonly UIntPtr64 UnicodeCaseTableData;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xB8)] internal readonly uint NumberOfProcessors;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xBC)] internal readonly uint NtGlobalFlag;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xC0)] internal readonly long CriticalSectionTimeout;

    #region Appended for Windows NT 3.51
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xC8)] internal readonly UIntPtr64 HeapSegmentReserve;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xD0)] internal readonly UIntPtr64 HeapSegmentCommit;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xD8)] internal readonly UIntPtr64 HeapDeCommitTotalFreeThreshold;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xE0)] internal readonly UIntPtr64 HeapDeCommitFreeBlockThreshold;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xE8)] internal readonly uint NumberOfHeaps;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xEC)] internal readonly uint MaximumNumberOfHeaps;
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xF0)] internal readonly UIntPtr64<UIntPtr64> ProcessHeaps;
    #endregion Appended for Windows NT 3.51

    #region Appended for Windows NT 4.0
    /// <summary>Compatibility: 3.51 and higher</summary>
    [FieldOffset(0xF8)] internal readonly UIntPtr64 GdiSharedHandleTable;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0100)] internal readonly UIntPtr64 ProcessTarterHelper;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0108)] internal readonly uint GdiDCAttributeList;
    /// <summary>Compatibility: 4.0 to 5.1</summary>
    [FieldOffset(0x0110), Obsolete] private readonly UIntPtr64 LoaderLock_obsolete;
    /// <summary>Compatibility: 5.2 and higher</summary>
    [FieldOffset(0x0110)] internal readonly UIntPtr64<RTL_CRITICAL_SECTION64> LoaderLock;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0118)] internal readonly uint OSMajorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x011C)] internal readonly uint OSMinorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0120)] internal readonly ushort OSBuildNumber;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0122)] internal readonly ushort OSCSDVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0124)] internal readonly uint OSPlatformId;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0128)] internal readonly uint ImageSubsystem;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x012C)] internal readonly uint ImageSubsystemMajorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    [FieldOffset(0x0130)] internal readonly uint ImageSubsystemMinorVersion;
    /// <summary>Compatibility: 4.0 to early 6.0</summary>
    [FieldOffset(0x0138), Obsolete] private readonly KAFFINITY64 ImageProcessAffinityMask;
    /// <summary>Compatibility: late 6.0 and higher</summary>
    [FieldOffset(0x0138)] internal readonly KAFFINITY64 ActiveProcessAffinityMask;
    /// <summary>(only 0x22 array members instead of 0x3C) Compatibility: 4.0 to early 6.0</summary>
    [FieldOffset(0x0140), Obsolete] private unsafe fixed uint GdiHandleBuffer_obsolete[0x22];
    /// <summary>4.0 and higher (x86)</summary>
    [FieldOffset(0x0140)] internal unsafe fixed uint GdiHandleBuffer[0x3C];
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
    /// Type: <see cref="PPS_POST_PROCESS_INIT_ROUTINE"/>
    /// Not supported</summary>
    [FieldOffset(0x0230)] internal readonly UIntPtr64 PostProcessInitRoutine;
    /// <summary>Compatibility: 5.0 and higher</summary>
    [FieldOffset(0x0238)] internal readonly UIntPtr64 TlsExpansionBitmap;
    /// <summary>Compatibility: 5.0 and higher</summary>
    [FieldOffset(0x0240)] internal unsafe fixed uint TlsExpansionBitmapBits[0x20];
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
    [FieldOffset(0x02C0)] internal readonly uint SessionId;

    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x02C8)] internal readonly PEB_AppCompat AppCompatFlags;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x02D0)] internal readonly PEB_AppCompat AppCompatFlagsUser;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x02D8)] internal readonly UIntPtr64 pShimData;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x02E0)] internal readonly UIntPtr64 AppCompatInfo;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x02E8)] internal readonly UNICODE_STRING64 CSDVersion;
    #endregion Appended for Windows 2000

    #region Appended for Windows XP
    /// <summary>Compatibility: 5.1 and higher<br/>
    /// Type: ACTIVATION_CONTEXT_DATA const * (pointer to a constant ACTIVATION_CONTEXT_DATA)</summary>
    [FieldOffset(0x02F8)] internal readonly UIntPtr64 ActivationContextData;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ACTIVATION_CONTEXT_DATA *</summary>
    [FieldOffset(0x0300)] internal readonly UIntPtr64 ProcessAssemblyStorageMap;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ACTIVATION_CONTEXT_DATA const *</summary>
    [FieldOffset(0x0308)] internal readonly UIntPtr64 SystemDefaultActivationContextData;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ASSEMBLY_STORAGE_MAP *</summary>
    [FieldOffset(0x310)] internal readonly UIntPtr64 SystemAssemblyStorageMap;
    /// <summary>Compatibility: 5.1 and higher</summary>
    [FieldOffset(0x318)] internal readonly UIntPtr64 MinimumStackCommit;
    #endregion Appended for Windows XP

    #region Appended for Windows Server 2003
    /// <summary>Compatibility: 5.2 to 1809
    /// Type: FLS_CALLBACK_INFO *</summary>
    [FieldOffset(0x0320)] internal readonly UIntPtr64 FlsCallback;
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x0328)] internal readonly LIST_ENTRY64 FlatListHead; // 5.2 to 1809
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x0338)] internal readonly UIntPtr64 FlsBitmap;
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x0340)] internal unsafe fixed uint FlsBitmapBits[4];
    /// <summary>Compatibility: 5.2 to 1809</summary>
    [FieldOffset(0x0350)] internal readonly uint FlsHighIndex;
    #endregion Appended for Windows Server 2003

    #region Appended for Windows Vista
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x0358)] internal readonly UIntPtr64 WerRegistrationData;
    /// <summary>Compatibility: 6.0 and higher</summary>
    [FieldOffset(0x0360)] internal readonly UIntPtr64 WerShipAssertPtr;
    #endregion Appended for Windows Vista

    #region Appended for Windows 7
    /// <summary>Compatibility: 6.1 only</summary>
    [FieldOffset(0x0368)] internal readonly UIntPtr64 pContextData;
    /* [FieldOffset(0x0238)] internal readonly UIntPtr64 pUnused; */
    /// <summary>Compatibility: 6.1 and higher</summary>
    [FieldOffset(0x0370)] internal readonly UIntPtr64 pImageHeaderHash;
    [FieldOffset(0x0378)] internal readonly PEB_Tracing TracingFlags;
    #endregion Appended for Windows 7

    #region Appended for Windows 8
    /// <summary>Compatibility: 6.2 and higher</summary>
    [FieldOffset(0x0380)] internal readonly ulong CsrServerReadOnlySharedMemoryBase;
    #endregion Appended for Windows 8

    #region Appended Later in Windows 10
    /// <summary>Compatibility: 1511 and higher</summary>
    [FieldOffset(0x0388)] internal readonly uint TppWorkerpListLock;
    /// <summary>Compatibility: 1511 and higher</summary>
    [FieldOffset(0x0390)] internal readonly LIST_ENTRY64 TppWorkerList;
    /// <summary>Compatibility: 1511 and higher<br/>
    /// Type: Fixed Array of void*</summary>
    [FieldOffset(0x03A0)] internal unsafe fixed ulong WaitOnAddressHashTable[0x80];
    /// <summary>Compatibility: 1709 and higher</summary>
    [FieldOffset(0x07A0)] internal readonly UIntPtr64 TelemetryCoverageHeader;
    /// <summary>Compatibility: 1709 and higher</summary>
    [FieldOffset(0x07A8)] internal readonly uint CloudFileFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    [FieldOffset(0x07AC)] internal readonly uint CloudFileDiagFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    [FieldOffset(0x07B0)] internal readonly byte PlaceholderCompatibilityMode;
    /// <summary>Compatibility: 1803 and higher
    /// Type: LEAP_SECOND_DATA *</summary>
    [FieldOffset(0x07B8)] internal readonly UIntPtr64 LeapSecondData;
    [FieldOffset(0x07C0)] internal readonly PEB_LeapSecond LeapSecondFlags;
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
    [FieldOffset(0x07C4)] internal readonly uint NtGlobalFlag2;
    #endregion Appended Later in Windows 10
}
