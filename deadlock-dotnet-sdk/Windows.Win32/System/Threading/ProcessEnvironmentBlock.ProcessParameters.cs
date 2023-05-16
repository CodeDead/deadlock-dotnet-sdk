using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32.Foundation;
using static Windows.Win32.System.Threading.RTL_USER_PROCESS_PARAMETERS32;
using static Windows.Win32.System.Threading.RTL_USER_PROCESS_PARAMETERS64;
using Code = PInvoke.NTSTATUS.Code;
using Env = System.Environment;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;
using Win32Exception = PInvoke.Win32Exception;

namespace Windows.Win32.System.Threading;

public partial class ProcessEnvironmentBlock
{
    public class UserProcessParameters
    {
        public UserProcessParameters(RTL_USER_PROCESS_PARAMETERS32 rupp32)
        {
            CommandLine.w32 = rupp32.CommandLine;
            ConsoleFlags = rupp32.ConsoleFlags;
            ConsoleHandle.w32 = rupp32.ConsoleHandle;
            CountCharsX = rupp32.CountCharsX;
            CountCharsY = rupp32.CountCharsY;
            CountX = rupp32.CountX;
            CountY = rupp32.CountCharsY;
            CurrentDirectories.w32 = rupp32.CurrentDirectories;
            CurrentDirectory.w32 = rupp32.CurrentDirectory;
            DebugFlags = rupp32.DebugFlags;
            DefaultThreadpoolCpuSetMaskCount = rupp32.DefaultThreadpoolCpuSetMaskCount;
            DefaultThreadpoolCpuSetMasks.w32 = rupp32.DefaultThreadpoolCpuSetMasks;
            DefaultThreadpoolThreadMaximum = rupp32.DefaultThreadpoolThreadMaximum;
            DesktopInfo.w32 = rupp32.DesktopInfo;
            DllPath.w32 = rupp32.DllPath;
            Environment.w32 = rupp32.Environment;
            EnvironmentSize.w32 = rupp32.EnvironmentSize;
            EnvironmentVersion.w32 = rupp32.EnvironmentVersion;
            FillAttribute = rupp32.FillAttribute;
            Flags = rupp32.Flags;
            HeapPartitionName.w32 = rupp32.HeapPartitionName;
            ImagePathName.w32 = rupp32.ImagePathName;
            Length = rupp32.Length;
            LoaderThreads = rupp32.LoaderThreads;
            MaximumLength = rupp32.MaximumLength;
            PackageDependencyData.w32 = rupp32.PackageDependencyData;
            ProcessGroupId = rupp32.ProcessGroupId;
            RedirectionDllName.w32 = rupp32.RedirectionDllName;
            RuntimeData.w32 = rupp32.RuntimeData;
            ShellInfo.w32 = rupp32.ShellInfo;
            ShowWindowFlags = rupp32.ShowWindowFlags;
            StandardError.w32 = rupp32.StandardError;
            StandardInput.w32 = rupp32.StandardInput;
            StandardOutput.w32 = rupp32.StandardOutput;
            StartingX = rupp32.StartingX;
            StartingY = rupp32.StartingY;
            WindowFlags = rupp32.WindowFlags;
            WindowTitle.w32 = rupp32.WindowTitle;
        }

        public UserProcessParameters(RTL_USER_PROCESS_PARAMETERS64 rupp64)
        {
            CommandLine.w64 = rupp64.CommandLine;
            ConsoleFlags = rupp64.ConsoleFlags;
            ConsoleHandle.w64 = rupp64.ConsoleHandle;
            CountCharsX = rupp64.CountCharsX;
            CountCharsY = rupp64.CountCharsY;
            CountX = rupp64.CountX;
            CountY = rupp64.CountCharsY;
            CurrentDirectories.w64 = rupp64.CurrentDirectories;
            CurrentDirectory.w64 = rupp64.CurrentDirectory;
            DebugFlags = rupp64.DebugFlags;
            DefaultThreadpoolCpuSetMaskCount = rupp64.DefaultThreadpoolCpuSetMaskCount;
            DefaultThreadpoolCpuSetMasks.w64 = rupp64.DefaultThreadpoolCpuSetMasks;
            DefaultThreadpoolThreadMaximum = rupp64.DefaultThreadpoolThreadMaximum;
            DesktopInfo.w64 = rupp64.DesktopInfo;
            DllPath.w64 = rupp64.DllPath;
            Environment.w64 = rupp64.Environment;
            EnvironmentSize.w64 = rupp64.EnvironmentSize;
            EnvironmentVersion.w64 = rupp64.EnvironmentVersion;
            FillAttribute = rupp64.FillAttribute;
            Flags = rupp64.Flags;
            HeapPartitionName.w64 = rupp64.HeapPartitionName;
            ImagePathName.w64 = rupp64.ImagePathName;
            Length = rupp64.Length;
            LoaderThreads = rupp64.LoaderThreads;
            MaximumLength = rupp64.MaximumLength;
            PackageDependencyData.w64 = rupp64.PackageDependencyData;
            ProcessGroupId = rupp64.ProcessGroupId;
            RedirectionDllName.w64 = rupp64.RedirectionDllName;
            RuntimeData.w64 = rupp64.RuntimeData;
            ShellInfo.w64 = rupp64.ShellInfo;
            ShowWindowFlags = rupp64.ShowWindowFlags;
            StandardError.w64 = rupp64.StandardError;
            StandardInput.w64 = rupp64.StandardInput;
            StandardOutput.w64 = rupp64.StandardOutput;
            StartingX = rupp64.StartingX;
            StartingY = rupp64.StartingY;
            WindowFlags = rupp64.WindowFlags;
            WindowTitle.w64 = rupp64.WindowTitle;
        }

        public uint MaximumLength;
        public uint Length;

        public uint Flags;
        public uint DebugFlags;

        public (HANDLE32? w32, HANDLE64? w64) ConsoleHandle;
        public uint ConsoleFlags;
        public (HANDLE32? w32, HANDLE64? w64) StandardInput;
        public (HANDLE32? w32, HANDLE64? w64) StandardOutput;
        public (HANDLE32? w32, HANDLE64? w64) StandardError;

        public (CURDIR32? w32, CURDIR64? w64) CurrentDirectory;
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) DllPath;
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) ImagePathName;
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) CommandLine;

        /// <summary>
        /// Using a SafeProcessHandle with <c>PROCESS_VM_READ</c> access, copy the target process's command line string.
        /// </summary>
        /// <param name="processHandle">A SafeProcessHandle with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ"/></param>
        /// <returns>A string containing the path of the executable image followed by the process's startup parameters.</returns>
        /// <exception cref="NullReferenceException">Unable to get Command Line; The pointers for the 32-bit and 64-bit data are both null.</exception>
        /// <exception cref="AccessViolationException">Failed to get Command Line; The process attempted to read protected memory.</exception>
        /// <exception cref="Exception">Failed to get Command Line; (system-provided message)</exception>
        public unsafe string GetCommandLine(SafeProcessHandle processHandle)
        {
            // If Resource strings are desired (e.g. for localizations), try using ResJ instead of ResX!
            const string unableMsg = "Unable to get Command Line; ";
            const string failedMsg = "Failed to get Command Line; ";
            const string nullPtrsMsg = "The pointers for the 32-bit and 64-bit data are both null.";
            const string protectedMemMsg = "The process attempted to read protected memory.";

            if (CommandLine is (null, null))
                throw new NullReferenceException(unableMsg + nullPtrsMsg);

            using UNICODE_STRING cmdLine = new()
            {
                Buffer = (char*)Marshal.AllocHGlobal(CommandLine.w32?.MaximumLength ?? CommandLine.w64?.MaximumLength ?? default),
                Length = CommandLine.w32?.Length ?? CommandLine.w64?.Length ?? default,
                MaximumLength = CommandLine.w32?.MaximumLength ?? CommandLine.w64?.MaximumLength ?? default
            };

            if (!Env.Is64BitProcess && CommandLine.w64 is not null) // we are 32-bit; they are 64-bit
            {
                ulong bytesRead;
                NTSTATUS status;

                if ((status = PInvoke.NtWow64ReadVirtualMemory64(processHandle, (UIntPtr64)CommandLine.w64.Value.Buffer.Value, cmdLine.Buffer.Value, cmdLine.Length, &bytesRead)).Code is Code.STATUS_SUCCESS)
                    return cmdLine.ToStringLength();

                if (status.Code is Code.STATUS_PARTIAL_COPY)
                    throw new AccessViolationException(failedMsg + protectedMemMsg, new NTStatusException(status));
                else
                    throw new Exception(failedMsg + status.Message, new NTStatusException(status));
            }
            else
            {
                nuint bytesRead;

                if (CommandLine.w32 is not null && PInvoke.ReadProcessMemory(processHandle, (char*)CommandLine.w32.Value.Buffer, cmdLine.Buffer.Value, cmdLine.Length, &bytesRead))
                    return cmdLine.ToStringLength();
                else if (CommandLine.w64 is not null && PInvoke.ReadProcessMemory(processHandle, (char*)CommandLine.w64.Value.Buffer, cmdLine.Buffer.Value, cmdLine.Length, &bytesRead))
                    return cmdLine.ToStringLength();

                Win32ErrorCode err = (Win32ErrorCode)Marshal.GetLastPInvokeError();
                if (err is Win32ErrorCode.ERROR_PARTIAL_COPY)
                    throw new AccessViolationException(failedMsg + protectedMemMsg, new Win32Exception(err));
                else
                    throw new Exception(failedMsg + err.GetMessage(), new Win32Exception(err));
            }
        }

        public (UIntPtr32? w32, UIntPtr64? w64) Environment;

        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;

        public uint WindowFlags;
        public uint ShowWindowFlags;
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) WindowTitle;
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) DesktopInfo;
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) ShellInfo;
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) RuntimeData;

        public (RTL_DRIVE_LETTER_CURDIR32[]? w32, RTL_DRIVE_LETTER_CURDIR64[]? w64) CurrentDirectories;

        public (UIntPtr32? w32, UIntPtr64? w64) EnvironmentSize;
        public (UIntPtr32? w32, UIntPtr64? w64) EnvironmentVersion;

        public (UIntPtr32? w32, UIntPtr64? w64) PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;

        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) RedirectionDllName; // REDSTONE4
        public (UNICODE_STRING32? w32, UNICODE_STRING64? w64) HeapPartitionName; // 19H1
        public (UIntPtr32? w32, UIntPtr64? w64) DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }
}
