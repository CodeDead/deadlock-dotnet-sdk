using System.Runtime.InteropServices;

namespace Windows.Win32.System.Kernel;

/// <summary>
/// <para>NT 6.2  (Win8) and higher</para>
/// <para><see href="https://web.archive.org/web/20210826002650/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/rtl_balanced_node.htm"/></para>
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 0x18)]
internal unsafe struct RTL_BALANCED_NODE64
{
    [FieldOffset(0x00)] internal fixed uint _Children[2];
    internal UIntPtr64<RTL_BALANCED_NODE64>[] Children => new UIntPtr64<RTL_BALANCED_NODE64>[] { _Children[0], _Children[1] };
    [FieldOffset(0x00)] internal UIntPtr64<RTL_BALANCED_NODE64> Left;
    [FieldOffset(0x08)] internal UIntPtr64<RTL_BALANCED_NODE64> Right;

    [FieldOffset(0x10)] internal UIntPtr64 ParentValue;
    /// <summary>applies if the node is in a Red Black tree</summary>
    internal byte Red => (byte)(ParentValue & 0b1);
    /// <summary>applies if the node is in an AVL tree</summary>
    internal byte Balance => (byte)((ParentValue >> 1) & 0b11);
}
