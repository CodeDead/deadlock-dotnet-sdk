using System.Runtime.InteropServices;

namespace Windows.Win32.System.Kernel;

/// <summary>
/// <para>NT 6.2  (Win8) and higher</para>
/// <para><see href="https://web.archive.org/web/20210826002650/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/rtl_balanced_node.htm"/></para>
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 0x18)]
public unsafe struct RTL_BALANCED_NODE64
{
    [FieldOffset(0x00)] private fixed uint _Children[2];
    public UIntPtr64<RTL_BALANCED_NODE64>[] Children => new UIntPtr64<RTL_BALANCED_NODE64>[] { _Children[0], _Children[1] };
    [FieldOffset(0x00)] private UIntPtr64/* <RTL_BALANCED_NODE64> */ left;
    [FieldOffset(0x08)] private UIntPtr64/* <RTL_BALANCED_NODE64> */ right;

    [FieldOffset(0x10)] public UIntPtr64 ParentValue;
    /// <summary>applies if the node is in a Red Black tree</summary>
    public byte Red => (byte)(ParentValue & 0b1);
    /// <summary>applies if the node is in an AVL tree</summary>
    public byte Balance => (byte)((ParentValue >> 1) & 0b11);

    public UIntPtr64<RTL_BALANCED_NODE64> Left { get => (UIntPtr64<RTL_BALANCED_NODE64>)left; set => left = (UIntPtr64)value; }
    public UIntPtr64<RTL_BALANCED_NODE64> Right { get => (UIntPtr64<RTL_BALANCED_NODE64>)right; set => right = (UIntPtr64)value; }
}
