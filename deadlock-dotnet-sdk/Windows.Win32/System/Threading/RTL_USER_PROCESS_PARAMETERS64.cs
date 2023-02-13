using System.Runtime.InteropServices;
using Windows.Win32.Foundation;

namespace Windows.Win32.System.Threading;

[StructLayout(LayoutKind.Explicit)]
internal partial struct RTL_USER_PROCESS_PARAMETERS64
{
    [FieldOffset(0x00)] public uint MaximumLength;
    [FieldOffset(0x04)] public uint Length;

    [FieldOffset(0x08)] public uint Flags;
    [FieldOffset(0x0C)] public uint DebugFlags;

    [FieldOffset(0x10)] public HANDLE64 ConsoleHandle;
    [FieldOffset(0x18)] public uint ConsoleFlags;
    [FieldOffset(0x20)] public HANDLE64 StandardInput;
    [FieldOffset(0x28)] public HANDLE64 StandardOutput;
    [FieldOffset(0x30)] public HANDLE64 StandardError;

    [FieldOffset(0x38)] public CURDIR64 CurrentDirectory;
    [FieldOffset(0x50)] public UNICODE_STRING64 DllPath;
    [FieldOffset(0x60)] public UNICODE_STRING64 ImagePathName;
    [FieldOffset(0x70)] public UNICODE_STRING64 CommandLine;
    [FieldOffset(0x80)] public UIntPtr64 Environment; // 64-bit pointer

    [FieldOffset(0x88)] public uint StartingX;
    [FieldOffset(0x8C)] public uint StartingY;
    [FieldOffset(0x90)] public uint CountX;
    [FieldOffset(0x94)] public uint CountY;
    [FieldOffset(0x98)] public uint CountCharsX;
    [FieldOffset(0x9C)] public uint CountCharsY;
    [FieldOffset(0xA0)] public uint FillAttribute;

    [FieldOffset(0xA4)] public uint WindowFlags;
    [FieldOffset(0xA8)] public uint ShowWindowFlags;
    [FieldOffset(0xB0)] public UNICODE_STRING64 WindowTitle;
    [FieldOffset(0xC0)] public UNICODE_STRING64 DesktopInfo;
    [FieldOffset(0xD0)] public UNICODE_STRING64 ShellInfo;
    [FieldOffset(0xE0)] public UNICODE_STRING64 RuntimeData;

    const int RTL_MAX_DRIVE_LETTERS = 0x20;
    // note: CurrentDirectories is misspelled as CurrentDirectores in the original definition
    [FieldOffset(0xF0)] public unsafe fixed byte _currentDirectories[RTL_MAX_DRIVE_LETTERS * 0x18/* sizeof(RTL_DRIVE_LETTER_CURDIR64) */];
    //public unsafe fixed RTL_DRIVE_LETTER_CURDIR _pCurrentDirectories[RTL_MAX_DRIVE_LETTERS];
    public unsafe RTL_DRIVE_LETTER_CURDIR64[] CurrentDirectories
    {
        get
        {
            fixed (byte* pCurrentDirectories = &_currentDirectories[0])
                return new ReadOnlySpan<RTL_DRIVE_LETTER_CURDIR64>(&pCurrentDirectories, RTL_MAX_DRIVE_LETTERS).ToArray();
        }
    }

    [FieldOffset(0x03F0)] public UIntPtr64 EnvironmentSize;
    [FieldOffset(0x03F8)] public UIntPtr64 EnvironmentVersion;

    [FieldOffset(0x0400)] public UIntPtr64 PackageDependencyData;
    [FieldOffset(0x0408)] public uint ProcessGroupId;
    [FieldOffset(0x040C)] public uint LoaderThreads;

    [FieldOffset(0x0410)] public UNICODE_STRING64 RedirectionDllName; // REDSTONE4
    [FieldOffset(0x0420)] public UNICODE_STRING64 HeapPartitionName; // 19H1
    [FieldOffset(0x0430)] public UIntPtr64 DefaultThreadpoolCpuSetMasks;
    [FieldOffset(0x0438)] public uint DefaultThreadpoolCpuSetMaskCount;
    [FieldOffset(0x043C)] public uint DefaultThreadpoolThreadMaximum;
}
