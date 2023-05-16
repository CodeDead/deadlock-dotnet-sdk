// https://web.archive.org/web/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
using System.Runtime.InteropServices;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;

namespace Windows.Win32.System.WindowsProgramming;
[StructLayout(LayoutKind.Explicit)]
public struct LDR_DATA_TABLE_ENTRY32
{
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x00)] internal readonly LIST_ENTRY32 InLoadOrderLinks;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x08)] internal readonly LIST_ENTRY32 InMemoryOrderLinks;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x10)] internal readonly LIST_ENTRY32 InInitializationOrderLinks;
    /// <summary>6.2 (Win8) and higher</summary>
    [FieldOffset(0x10)] internal readonly LIST_ENTRY32 InProgressLinks;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x18)] internal readonly UIntPtr32 DllBase;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x1C)] internal readonly UIntPtr32 Entrypoint;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x20)] internal readonly uint SizeOfImage;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x24)] internal readonly UNICODE_STRING32 FullDllName;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x2C)] internal readonly UNICODE_STRING32 BaseDllName;
    /// <summary>6.2 (Win8) and higher</summary>
    [FieldOffset(0x34)] internal unsafe fixed byte FlagGroup[4];
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x34)] internal readonly LdrEntryFlags Flags;
    /// <summary>3.10 to 6.1 (Win7)</summary>
    [FieldOffset(0x38)] internal readonly ushort LoadCount;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x38)] internal readonly ushort ObsoleteLoadCount;
    /// <summary>all</summary>
    [FieldOffset(0x3A)] internal readonly ushort TlsIndex;
    /// <summary>3.10 and higher</summary>
    [FieldOffset(0x3C)] internal readonly LIST_ENTRY32 HashLinks;
    /// <summary>3.10 to 6.1 (Win7)</summary>
    [FieldOffset(0x3C)] internal readonly UIntPtr32 SectionPointer;
    /// <summary>3.10 to 6.1  (Win7)</summary>
    [FieldOffset(0x3C)] internal readonly uint CheckSum;

    #region Appended for Windows NT 4.0 
    /// <summary>4.0 and higher</summary>
    [FieldOffset(0x44)] internal readonly uint TimeDateStamp;
    /// <summary>4.0 to 6.1</summary>
    [FieldOffset(0x44)] internal readonly UIntPtr32 LoadedImports;
    #endregion Appended for Windows NT 4.0 

    #region Appended for Windows XP
    /// <summary>5.1 and higher</summary>
    [FieldOffset(0x48)] internal readonly UIntPtr32 EntryPointActivationContext;
    /// <summary>5.1 from Windows XP SP2 to 6.2 (Win8)</summary>
    [FieldOffset(0x4C)] internal readonly UIntPtr32 PatchInformation;
    /// <summary>6.3 only</summary>
    [FieldOffset(0x4C)] internal readonly UIntPtr32 Spare;
    /// <summary>10.0 and higher</summary>
    [FieldOffset(0x4C)] internal readonly UIntPtr32 Lock;
    #endregion Appended for Windows XP

    #region Appended for Windows Vista
    /// <summary>6.0 to 6.1</summary>
    [FieldOffset(0x50)] internal readonly LIST_ENTRY32 ForwarderLinks;
    /// <summary>6.0 to 6.1</summary>
    [FieldOffset(0x58)] internal readonly LIST_ENTRY32 ServiceTagLinks;
    /// <summary>6.0 to 6.1</summary>
    [FieldOffset(0x60)] internal readonly LIST_ENTRY32 StaticLinks;
    #endregion Appended for Windows Vista

    #region Redone for Windows 8 
    /// <summary>(LDR_DDAG_NODE*) 6.2 and higher</summary>
    [FieldOffset(0x50)] internal readonly UIntPtr32 DdagNode;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x54)] internal readonly LIST_ENTRY32 NodeModuleLink;
    /// <summary>(LDRP_DLL_SNAP_CONTEXT*) 6.2 to 6.3</summary>
    [FieldOffset(0x5C)] internal readonly UIntPtr32 SnapContext;
    /// <summary>(LDRP_LOAD_CONTEXT*) 10.0 and higher</summary>
    [FieldOffset(0x5C)] internal readonly UIntPtr32 LoadContext;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x60)] internal readonly UIntPtr32 ParentBaseDll;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x64)] internal readonly UIntPtr32 SwitchBackContext;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x68)] internal readonly RTL_BALANCED_NODE32 BaseAddressIndexNode;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x70)] internal readonly RTL_BALANCED_NODE32 MappingInfoIndexNode;
    #endregion Redone for Windows 8 

    #region Appended for Windows 7
    /// <summary>6.1 only</summary>
    [FieldOffset(0x68)] internal readonly UIntPtr32 ContextInformation;
    /// <summary>6.1 only</summary>
    [FieldOffset(0x6C)] internal readonly UIntPtr32 OriginalBase_NT61;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x80)] internal readonly UIntPtr32 OriginalBase_NT62;
    /// <summary>6.1 only</summary>
    [FieldOffset(0x70)] internal readonly long LoadTime_NT61;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x88)] internal readonly long LoadTime_NT62;
    #endregion Appended for Windows 7

    #region Appended for Windows 8 
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x90)] internal readonly uint BaseNameHashValue;
    /// <summary>6.2 and higher</summary>
    [FieldOffset(0x94)] internal readonly LDR_DLL_LOAD_REASON LoadReason;
    #endregion Appended for Windows 8 

    #region Appended for Windows 8.1
    /// <summary>6.3 and higher</summary>
    [FieldOffset(0x98)] internal readonly uint ImplicitPathOptions;
    #endregion Appended for Windows 8.1

    #region Appended for Windows 10
    /// <summary>10.0 and higher</summary>
    [FieldOffset(0x9C)] internal readonly uint ReferenceCount;
    /// <summary>1607 and higher</summary>
    [FieldOffset(0xA0)] internal readonly uint DependentLoadFlags;
    /// <summary>1703 and higher</summary>
    [FieldOffset(0xA4)] internal readonly byte SigningLevel;

    #endregion Appended for Windows 10
}
