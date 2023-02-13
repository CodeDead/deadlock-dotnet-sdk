using System.Runtime.InteropServices;

namespace Windows.Win32.System.Kernel;

/// <summary>
/// <para>NT 6.2  (Win8) and higher</para>
/// <para><see href="https://web.archive.org/web/20210826002650/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/rtl_balanced_node.htm"/></para>
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 0x0C)]
internal unsafe struct RTL_BALANCED_NODE32
{
    [FieldOffset(0x00)] internal fixed uint _Children[2];
    internal UIntPtr32<RTL_BALANCED_NODE32>[] Children => new UIntPtr32<RTL_BALANCED_NODE32>[] { _Children[0], _Children[1] };
    [FieldOffset(0x00)] internal UIntPtr32<RTL_BALANCED_NODE32> Left;
    [FieldOffset(0x04)] internal UIntPtr32<RTL_BALANCED_NODE32> Right;

    [FieldOffset(0x08)] internal UIntPtr32 ParentValue;
    /// <summary>applies if the node is in a Red Black tree</summary>
    internal byte Red => (byte)(ParentValue & 0b1);
    /// <summary>applies if the node is in an AVL tree</summary>
    internal byte Balance => (byte)((ParentValue >> 1) & 0b11);
}
