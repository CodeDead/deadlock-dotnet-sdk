using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Threading;
using Windows.Win32.System.WindowsProgramming;
using static PInvoke.Kernel32;
using static PInvoke.NTSTATUS.Code;
using static Windows.Win32.PInvoke;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;

namespace deadlock_dotnet_sdk.Domain;

internal static partial class NativeMethods
{
    private static List<ObjectTypeInformation>? objectTypes;
    private static List<ObjectTypeInformation> ObjectTypes => objectTypes ??= ObjectTypesInformationBuffer.GetObjectTypes().ToList();

    /// <summary><para>
    /// The
    ///     <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_table_entry_ex.htm">
    ///     SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX</see>
    /// structure is a recurring element in the
    ///     <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm">
    ///     SYSTEM_HANDLE_INFORMATION_EX</see>
    /// struct that a successful call to
    ///     <see href="https://docs.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation">
    ///     ZwQuerySystemInformation</see>
    /// or
    ///     <see href="https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation">
    ///     NtQuerySystemInformation</see>
    /// produces in its output buffer when given the information class <see cref="SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation">
    /// SystemExtendedHandleInformation (0x40)</see>.</para>
    /// This inline doc was supplemented by ProcessHacker's usage of this struct.
    /// </summary>
    public readonly struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
#pragma warning disable CS0649
        public nuint Object { get; }
        /// <summary>ULONG_PTR, cast to HANDLE, int, or uint</summary>
        public nuint UniqueProcessId { get; }
        /// <summary>ULONG_PTR, cast to HANDLE</summary>
        internal HANDLE HandleValue { get; }
        /// <summary>Get the HandleValue as a SafeObjectHandle. Closing this SafeObjectHandle does *not* close the source handle.</summary>
        public SafeObjectHandle GetSafeHandle() => new(HandleValue, false);
        /// <summary>This is a bitwise "Flags" data type.
        /// See the "Granted Access" column in the Handles section of a process properties window in ProcessHacker.</summary>
        [JsonIgnore]
        public ACCESS_MASK GrantedAccess { get; } // uint
        /// <summary>Note: SpecificRights requires the Type of `Object` and the code definitions of that Type's access rights.</summary>
        public string GrantedAccessString => $"0x{GrantedAccess.Value:X} ({GrantedAccess.SpecificRights}, {GrantedAccess.StandardRights}, {GrantedAccess.GenericRights})";
        public ushort CreatorBackTraceIndex { get; } // USHORT
        /// <summary>ProcessHacker defines a little over a dozen handle-able object types.</summary>
        public ushort ObjectTypeIndex { get; } // USHORT
        /// <summary><see href="https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes#members"/></summary>
        public HandleFlags HandleAttributes { get; } // uint
#pragma warning disable RCS1213, CS0169, IDE0051 // Remove unused field declaration. csharp(RCS1213) | Roslynator
        private readonly uint Reserved;
#pragma warning restore RCS1213, CS0649, CS0169, IDE0051

        /// <summary>Get the Type of the object as a string</summary>
        /// <exception cref="Exception">P/Invoke function NtQueryObject failed. See Exception data.</exception>
        /// <returns>The Type of the object as a string.</returns>
        public unsafe string GetHandleObjectType()
        {
            try
            {
                NTSTATUS status;
                using SafeBuffer<PUBLIC_OBJECT_TYPE_INFORMATION> buffer = new(numBytes: 256/* (nuint)Marshal.SizeOf<PUBLIC_OBJECT_TYPE_INFORMATION>() */);
                uint returnLength;
                using var h = new SafeObjectHandle(HandleValue, false);

                status = NtQueryObject(h, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, (void*)buffer.DangerousGetHandle(), (uint)buffer.ByteLength, &returnLength);

                // Something's off. Marshal.SizeOf() returns 0x68 (104) but returnLength is 0x78 (120) or sometimes 0x80 (128). Is Win32Metadata's type definition wrong?
                while (status.Code is STATUS_BUFFER_OVERFLOW or STATUS_INFO_LENGTH_MISMATCH or STATUS_BUFFER_TOO_SMALL)
                {
                    buffer.Reallocate(returnLength);
                    status = NtQueryObject(h, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, (void*)buffer.DangerousGetHandle(), (uint)buffer.ByteLength, &returnLength);
                }

                if (status == STATUS_INVALID_HANDLE || !status.IsSuccessful)
                    throw new NTStatusException(status);

                return (string)buffer.Read<PUBLIC_OBJECT_TYPE_INFORMATION>(0).TypeName;

                // return GetObjectTypeName(ObjectTypeIndex);
            }
            catch (Exception)
            {
                throw;
            }
        }

        internal unsafe HANDLE_FLAGS GetHandleInformation()
        {
            try
            {
                using SafeObjectHandle hObject = new(HandleValue, false);
                return Windows.Win32.PInvoke.GetHandleInformation(hObject);
            }
            catch (Exception ex)
            {
                Debug.Print(ex.ToString());
            }

            // If passing the source handle failed, try passing a duplicate instead

            using SafeProcessHandle sourceProcess = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, false, (uint)UniqueProcessId);
            if (sourceProcess is null) throw new Win32Exception();
            using SafeObjectHandle safeHandleValue = new(HandleValue, false);
            DuplicateHandle(sourceProcess, safeHandleValue, Process.GetCurrentProcess().SafeHandle, out SafeFileHandle dupHandle, default, false, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS);
            return Windows.Win32.PInvoke.GetHandleInformation(dupHandle);
        }

        /// <summary>Invokes <see cref="GetHandleObjectType()"/> and checks if the result is "File".</summary>
        /// <returns>True if the handle is for a file or directory.</returns>
        /// <remarks>Based on source of C/C++ projects <see href="https://www.x86matthew.com/view_post?id=hijack_file_handle">Hijack File Handle</see> and <see href="https://github.com/adamkramer/handle_monitor">Handle Monitor</see></remarks>
        /// <exception cref="Exception">Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. See InnerException for details.</exception>
        public bool IsFileHandle()
        {
            try
            {
                string type = GetHandleObjectType();
                return !string.IsNullOrWhiteSpace(type) && string.CompareOrdinal(type, "File") == 0;
            }
            catch (Exception e)
            {
                throw new Exception("Failed to determine if this handle's object is a file/directory. Error when calling NtQueryObject. See InnerException for details.", e);
            }
        }

        /// <summary>
        /// Try to cast this handle's <see cref="HandleValue"/> to a SafeFileHandle;
        /// </summary>
        /// <returns>A <see cref="SafeFileHandle"/> if this handle's object is a data/directory File.</returns>
        /// <exception cref="Exception">The handle's object is not a File -OR- perhaps NtQueryObject() failed. See <see cref="Exception.InnerException"/> for details.</exception>
        public SafeFileHandle ToSafeFileHandle()
        {
            return IsFileHandle()
                ? (new((nint)HandleValue, (int)UniqueProcessId == Environment.ProcessId))
                : throw new Exception("The handle's object is not a File -OR- NtQueryObject() failed. See InnerException for details.");
        }
    }

    internal sealed class ObjectTypesInformationBuffer : IDisposable
    {
        private IntPtr pointer;
        private uint bytes;

        public ObjectTypesInformationBuffer(uint lengthInBytes)
        {
            pointer = Marshal.AllocHGlobal((int)lengthInBytes);
            bytes = lengthInBytes;
        }

        public IntPtr Pointer => pointer;
        public uint SizeInBytes => bytes;
        public unsafe uint NumberOfTypes => ((OBJECT_TYPES_INFORMATION*)pointer)->NumberOfTypes;

        public unsafe List<ObjectTypeInformation> ToList()
        {
            var list = new List<ObjectTypeInformation>();
            var selection = PH_FIRST_OBJECT_TYPE((void*)pointer);
            list.Add(new(*selection));

            for (int i = 1; i < NumberOfTypes; i++)
            {
                selection = PH_NEXT_OBJECT_TYPE(selection);
                list.Add(new(*selection));
            }
            return list;
        }

        public unsafe void ReAllocate(uint lengthInBytes)
        {
            pointer = Marshal.ReAllocHGlobal(pointer, (IntPtr)lengthInBytes);
            bytes = lengthInBytes;
        }

        public void Dispose() => Marshal.FreeHGlobal(pointer);

        /// <summary>
        /// P/Invoke NtQueryObject for ObjectTypesInformation data.
        /// </summary>
        /// <returns>An <see cref="ObjectTypesInformationBuffer"/>, a wrapper for OBJECT_TYPES_INFORMATION, OBJECT_TYPE_INFORMATION, and the allocated memory they occupy.</returns>
        /// <exception cref="NTStatusException"></exception>
        /// <exception cref="PInvoke.NTStatusException"></exception>
        public static unsafe ObjectTypesInformationBuffer GetObjectTypes()
        {
            NTSTATUS status;
            using ObjectTypesInformationBuffer buffer = new(0x1000);
            uint returnLength;

            while ((status = NtQueryObject(
                null,
                OBJECT_INFORMATION_CLASS.ObjectTypesInformation,
                (void*)buffer.pointer,
                buffer.bytes,
                &returnLength
                )) == STATUS_INFO_LENGTH_MISMATCH)
            {
                // Fail if we're resizing the buffer to something very large.
                const uint PH_LARGE_BUFFER_SIZE = int.MaxValue;
                if (returnLength * 1.5 > PH_LARGE_BUFFER_SIZE)
                    throw new NTStatusException(STATUS_INSUFFICIENT_RESOURCES);

                buffer.ReAllocate((uint)(returnLength * 1.5));
            }

            status.ThrowOnError();

            return buffer;
        }
    }

    public static unsafe OBJECT_TYPE_INFORMATION* PH_FIRST_OBJECT_TYPE(void* ObjectTypes) => (OBJECT_TYPE_INFORMATION*)PTR_ADD_OFFSET(ObjectTypes, ALIGN_UP((nuint)sizeof(OBJECT_TYPES_INFORMATION), typeof(UIntPtr)));
    public static unsafe OBJECT_TYPE_INFORMATION* PH_NEXT_OBJECT_TYPE(OBJECT_TYPE_INFORMATION* ObjectType) => (OBJECT_TYPE_INFORMATION*)PTR_ADD_OFFSET(ObjectType, (nuint)Marshal.SizeOf<OBJECT_TYPE_INFORMATION>() + ALIGN_UP(ObjectType->TypeName.MaximumLength, typeof(UIntPtr)));
    public static unsafe void* PTR_ADD_OFFSET(void* Pointer, nuint Offset) => (void*)((nuint)Pointer + Offset);
    public static nuint ALIGN_UP(nuint Address, Type type) => ALIGN_UP_BY(Address, (uint)Marshal.SizeOf(type));
    public static nuint ALIGN_UP_BY(nuint Address, uint Align) => (Address + Align - 1) & ~(Align - 1);
}
