using System.Runtime.InteropServices;
using Windows.Win32.Foundation;

namespace Windows.Win32.System.Threading;

internal partial struct RTL_USER_PROCESS_PARAMETERS32
{
    /// <summary>
    /// See <see href="https://web.archive.org/web/https://geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/curdir.htm"/>
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = 0x0C)]
    internal struct CURDIR32
    {
        public UNICODE_STRING64 DosPath;
        public HANDLE64 Handle;
    }
}
