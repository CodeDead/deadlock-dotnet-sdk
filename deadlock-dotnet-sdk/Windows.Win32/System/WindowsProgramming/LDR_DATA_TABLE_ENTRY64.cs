using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;

namespace Windows.Win32.System.WindowsProgramming;
/// <summary>
/// https://web.archive.org/web/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal struct LDR_DATA_TABLE_ENTRY64
{
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x00)] internal readonly LIST_ENTRY64 InLoadOrderLinks;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x10)] internal readonly LIST_ENTRY64 InMemoryOrderLinks;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x20)] internal readonly LIST_ENTRY64 InInitializationOrderLinks;
    /// <summary>6.2 (Win8) and higher</summary>
    [FieldOffset(0x20)] internal readonly LIST_ENTRY64 InProgressLinks;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x30)] internal readonly UIntPtr64 DllBase;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x38)] internal readonly UIntPtr64 Entrypoint;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x40)] internal readonly uint SizeOfImage;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x48)] internal readonly UNICODE_STRING64 FullDllName;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x58)] internal readonly UNICODE_STRING64 BaseDllName;
    /// <summary>6.2 (Win8) and higher</summary>
    [FieldOffset(0x68)] internal unsafe fixed byte FlagGroup[4];
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x68)] internal readonly LdrEntryFlags Flags;
    /// <summary>3.10 to 6.1 (Win7). Obsolete on 6.2 (Win8) and higher.</summary>
    [FieldOffset(0x6C)] internal readonly ushort LoadCount;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x6C)] internal readonly ushort ObsoleteLoadCount;
    /// <summary>all</summary>
    [FieldOffset(0x6E)] internal readonly ushort TlsIndex;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x70)] internal readonly LIST_ENTRY64 HashLinks;
    /// <summary>3.10 to 6.1 (Win7). Obsolete on 6.2 (Win8) and higher.</summary>
    [FieldOffset(0x70)] internal readonly UIntPtr64 SectionPointer;
    /// <summary>3.10 to 6.1 (Win7). Obsolete on 6.2 (Win8) and higher.</summary>
    [FieldOffset(0x70)] internal readonly uint CheckSum; // 3.10 to 6.1  (Win7)

    #region Appended for Windows NT 4.0 
    /// <summary>4.0 and higher</summary>
    [FieldOffset(0x80)] internal readonly uint TimeDateStamp;
    /// <summary>4.0 to 6.1. Obsolete on 6.2 (Win8) and higher.</summary>
    [FieldOffset(0x80)] internal readonly UIntPtr64 LoadedImports;
    #endregion Appended for Windows NT 4.0 

    #region Appended for Windows XP
    /// <summary>5.1 and higher</summary>
    [FieldOffset(0x88)] internal UIntPtr64 EntryPointActivationContext;
    /// <summary>5.1 from Windows XP SP2 to 6.2 (Win8). Obsolete on 6.3 and higher.</summary>
    [FieldOffset(0x90)] internal readonly UIntPtr64 PatchInformation;
    /// <summary>6.3 only</summary>
    [FieldOffset(0x90)] internal readonly UIntPtr64 Spare;
    /// <summary>10.0 and higher</summary>
    [FieldOffset(0x90)] internal readonly UIntPtr64 Lock;
    #endregion Appended for Windows XP

    #region Appended for Windows Vista
    /// <summary>6.0 to 6.1 (Win7)</summary>
    [FieldOffset(0x98)] internal readonly LIST_ENTRY64 ForwarderLinks;
    /// <summary>6.0 to 6.1 (Win7)</summary>
    [FieldOffset(0xA8)] internal readonly LIST_ENTRY64 ServiceTagLinks;
    /// <summary>6.0 to 6.1 (Win7)</summary>
    [FieldOffset(0xB8)] internal readonly LIST_ENTRY64 StaticLinks;
    #endregion Appended for Windows Vista

    #region Redone for Windows 8 
    /// <summary>(LDR_DDAG_NODE*) 6.2 and higher</summary>
    [FieldOffset(0x98)] internal readonly UIntPtr64 DdagNode;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0xA0)] internal readonly LIST_ENTRY64 NodeModuleLink;
    /// <summary>(LDRP_DLL_SNAP_CONTEXT*) 6.2 to 6.3</summary>
    [FieldOffset(0xB0)] internal readonly UIntPtr64 SnapContext;
    /// <summary>(LDRP_LOAD_CONTEXT*) 10.0 and higher</summary>
    [FieldOffset(0xB0)] internal readonly UIntPtr64 LoadContext;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0xB8)] internal readonly UIntPtr64 ParentBaseDll;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0xC0)] internal readonly UIntPtr64 SwitchBackContext;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0xC8)] internal readonly RTL_BALANCED_NODE64 BaseAddressIndexNode;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0xE0)] internal readonly RTL_BALANCED_NODE64 MappingInfoIndexNode;
    #endregion Redone for Windows 8 

    #region Appended for Windows 7
    /// <summary>6.1 only</summary>
    [FieldOffset(0xC8)] internal readonly UIntPtr64 ContextInformation;
    /// <summary>6.1 only</summary>
    [FieldOffset(0xD0)] internal readonly UIntPtr64 OriginalBase_NT61;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0xF8)] internal readonly UIntPtr64 OriginalBase_NT62;
    /// <summary>6.1 only</summary>
    [FieldOffset(0xD8)] internal readonly long LoadTime_NT61;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x0100)] internal readonly long LoadTime_NT62;
    #endregion Appended for Windows 7

    #region Appended for Windows 8 
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x0108)] internal readonly uint BaseNameHashValue;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x010C)] internal readonly LDR_DLL_LOAD_REASON LoadReason;
    #endregion Appended for Windows 8 

    #region Appended for Windows 8.1
    /// <summary>6.3 and higher</summary>
    [FieldOffset(0x0110)] internal readonly uint ImplicitPathOptions;
    #endregion Appended for Windows 8.1

    #region Appended for Windows 10
    /// <summary>10.0 and higher</summary>
    [FieldOffset(0x0114)] internal readonly uint ReferenceCount;
    /// <summary>1607 and higher</summary>
    [FieldOffset(0x0118)] internal readonly uint DependentLoadFlags;
    /// <summary>1703 and higher</summary>
    [FieldOffset(0x011C)] internal readonly byte SigningLevel;
    #endregion Appended for Windows 10
}
