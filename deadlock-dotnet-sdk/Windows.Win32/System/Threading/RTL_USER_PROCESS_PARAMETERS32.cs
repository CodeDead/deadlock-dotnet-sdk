using System.Runtime.InteropServices;
using Windows.Win32.Foundation;

namespace Windows.Win32.System.Threading;

/// <inheritdoc cref="RTL_USER_PROCESS_PARAMETERS"/>
[StructLayout(LayoutKind.Explicit)]
internal partial struct RTL_USER_PROCESS_PARAMETERS32
{
    [FieldOffset(0x00)] public uint MaximumLength;
    [FieldOffset(0x04)] public uint Length;

    [FieldOffset(0x08)] public uint Flags;
    [FieldOffset(0x0C)] public uint DebugFlags;

    [FieldOffset(0x10)] public HANDLE32 ConsoleHandle;
    [FieldOffset(0x14)] public uint ConsoleFlags;
    [FieldOffset(0x18)] public HANDLE32 StandardInput;
    [FieldOffset(0x1C)] public HANDLE32 StandardOutput;
    [FieldOffset(0x20)] public HANDLE32 StandardError;

    [FieldOffset(0x24)] public CURDIR32 CurrentDirectory;
    [FieldOffset(0x30)] public UNICODE_STRING32 DllPath;
    [FieldOffset(0x38)] public UNICODE_STRING32 ImagePathName;
    [FieldOffset(0x40)] public UNICODE_STRING32 CommandLine;
    [FieldOffset(0x48)] public UIntPtr32 Environment; // 32-bit pointer

    [FieldOffset(0x4C)] public uint StartingX;
    [FieldOffset(0x50)] public uint StartingY;
    [FieldOffset(0x54)] public uint CountX;
    [FieldOffset(0x58)] public uint CountY;
    [FieldOffset(0x5C)] public uint CountCharsX;
    [FieldOffset(0x60)] public uint CountCharsY;
    [FieldOffset(0x64)] public uint FillAttribute;

    [FieldOffset(0x68)] public uint WindowFlags;
    [FieldOffset(0x6C)] public uint ShowWindowFlags;
    [FieldOffset(0x70)] public UNICODE_STRING32 WindowTitle;
    [FieldOffset(0x78)] public UNICODE_STRING32 DesktopInfo;
    [FieldOffset(0x80)] public UNICODE_STRING32 ShellInfo;
    [FieldOffset(0x88)] public UNICODE_STRING32 RuntimeData;

    const int RTL_MAX_DRIVE_LETTERS = 0x20;
    // note: CurrentDirectories is misspelled as CurrentDirectores in the original definition
    [FieldOffset(0x90)] public unsafe fixed byte _currentDirectories[RTL_MAX_DRIVE_LETTERS * 0x10 /* sizeof(RTL_DRIVE_LETTER_CURDIR32) */];
    //public unsafe fixed RTL_DRIVE_LETTER_CURDIR _pCurrentDirectories[RTL_MAX_DRIVE_LETTERS];
    public unsafe RTL_DRIVE_LETTER_CURDIR32[] CurrentDirectories
    {
        get
        {
            fixed (byte* pCurrentDirectories = &_currentDirectories[0])
                return new ReadOnlySpan<RTL_DRIVE_LETTER_CURDIR32>(&pCurrentDirectories, RTL_MAX_DRIVE_LETTERS).ToArray();
        }
    }

    [FieldOffset(0x0290)] public UIntPtr32 EnvironmentSize;
    [FieldOffset(0x0294)] public UIntPtr32 EnvironmentVersion;

    [FieldOffset(0x0298)] public UIntPtr32 PackageDependencyData;
    [FieldOffset(0x029C)] public uint ProcessGroupId;
    [FieldOffset(0x02A0)] public uint LoaderThreads;

    [FieldOffset(0x02A4)] public UNICODE_STRING32 RedirectionDllName; // REDSTONE4
    [FieldOffset(0x02AC)] public UNICODE_STRING32 HeapPartitionName; // 19H1
    [FieldOffset(0x02B4)] public UIntPtr32 DefaultThreadpoolCpuSetMasks;
    [FieldOffset(0x02B8)] public uint DefaultThreadpoolCpuSetMaskCount;
    [FieldOffset(0x02BC)] public uint DefaultThreadpoolThreadMaximum;
}
