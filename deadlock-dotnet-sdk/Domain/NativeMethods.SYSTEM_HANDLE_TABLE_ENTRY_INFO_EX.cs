using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Windows.Win32.Foundation;
using Windows.Win32.System.WindowsProgramming;
using static PInvoke.Kernel32;
using static Windows.Win32.PInvoke;
using Code = PInvoke.NTSTATUS.Code;

// Re: StructLayout
// "C#, Visual Basic, and C++ compilers apply the Sequential layout value to structures by default."
// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.structlayoutattribute?view=net-6.0#remarks

// new Win32Exception() is defined as
// public Win32Exception() : this(Marshal.GetLastPInvokeError())
// {
// }

namespace deadlock_dotnet_sdk.Domain;

internal static partial class NativeMethods
{
    private const uint PH_LARGE_BUFFER_SIZE = int.MaxValue;
    private static List<ObjectTypeInformation>? objectTypes;
    private static List<ObjectTypeInformation> ObjectTypes => objectTypes ??= ObjectTypesInformationBuffer.PhEnumObjectTypes().ToList();

    /// <summary>
    /// ported from SystemInformer for convenience
    /// </summary>
    private static uint? GetObjectTypeNumber(string typeName)
    {
        Version WINDOWS_8_1 = new(6, 2);
        Version WindowsVersion = Environment.OSVersion.Version;
        uint objectIndex = uint.MaxValue;

        for (int i = 0; i < ObjectTypes.Count; i++)
        {
            if (typeName.Equals(ObjectTypes[i].TypeName, StringComparison.OrdinalIgnoreCase))
            {
                if (WindowsVersion >= WINDOWS_8_1)
                    objectIndex = ObjectTypes[i].TypeIndex;
                else
                    objectIndex = (uint)(i + 2);
            }
        }

        if (objectIndex is uint.MaxValue)
            throw new InvalidOperationException("No matching Type found.");

        return objectIndex;
    }

    /// <summary>
    /// ported from SystemInformer for convenience
    /// </summary>
    private static string GetObjectTypeName(int typeIndex)
    {
        Version WINDOWS_8_1 = new(6, 2);
        Version WindowsVersion = Environment.OSVersion.Version;
        string objectTypeName = "";

        for (int i = 0; i < ObjectTypes.Count; i++)
        {
            if (WindowsVersion >= WINDOWS_8_1)
            {
                if (typeIndex == ObjectTypes[i].TypeIndex)
                    objectTypeName = ObjectTypes[i].TypeName;
            }
            else if (typeIndex == (i + 2))
            {
                objectTypeName = ObjectTypes[i].TypeName;
            }
        }

        if (objectTypeName is "")
            throw new InvalidOperationException("No matching Type found.");

        return objectTypeName;
    }

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
        private readonly unsafe void* Object;
        public unsafe nuint ObjectPointer => (nuint)Object;
        /// <summary>
        /// ULONG_PTR, cast to HANDLE, int, or uint
        /// </summary>
        public nuint UniqueProcessId { get; }
        /// <summary>
        /// ULONG_PTR, cast to HANDLE
        /// </summary>
        public HANDLE HandleValue { get; }
        /// <summary>
        /// This is a bitwise "Flags" data type.
        /// See the "Granted Access" column in the Handles section of a process properties window in ProcessHacker.
        /// </summary>
        public ACCESS_MASK GrantedAccess { get; } // uint
        public ushort CreatorBackTraceIndex { get; } // USHORT
        /// <summary>ProcessHacker defines a little over a dozen handle-able object types.</summary>
        public ushort ObjectTypeIndex { get; } // USHORT
        /// <summary><see href="https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes#members"/></summary>
        public HandleFlags HandleAttributes { get; } // uint
#pragma warning disable RCS1213, CS0169, IDE0051 // Remove unused field declaration. csharp(RCS1213) | Roslynator
        private readonly uint Reserved;
#pragma warning restore RCS1213, CS0649, CS0169, IDE0051

        /// <summary>
        /// Get the Type of the object as a string<br/>
        /// If calling from a SafeHandle
        /// </summary>
        /// <exception cref="Exception">P/Invoke function NtQueryObject failed. See Exception data.</exception>
        /// <returns>The Type of the object as a string.</returns>
        public unsafe string GetHandleObjectType()
        {
            /* CS1673: Anonymous methods, lambda expressions, query expressions, and local
            functions inside structs cannot access instance members of 'this'.
            Consider copying 'this' to a local variable outside the anonymous method, lambda
            expression, query expression, or local function and using the local instead.
            */
            return GetObjectTypeName(ObjectTypeIndex);

            //* Open a handle to the process associated with this system handle - adamkramer */

            //using SafeFileHandle? hProcess = OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, true, (uint)UniqueProcessId);
            //if (hProcess is null || hProcess!.IsInvalid) throw new System.ComponentModel.Win32Exception();

            //* Duplicate this system handle so we can query it. - adamkramer */
            /* sidebar: DuplicateHandle and NtDuplicateObject seem to have the same purpose, but are in the WinSDK and WDDK, respectively. Question is: Why? Why have two (technically three i.e. ZwDuplicateObject) functions that do the same thing? -BinToss */

            // if (0 <= NtDuplicateObject(hProcess, HandleValue, Process.GetCurrentProcess().SafeHandle))
            // {
            // }
            // 
            // if (DuplicateHandle(hSourceProcessHandle: hProcess,
            //                     hSourceHandle: new Kernel32.SafeObjectHandle(HandleValue),
            //                     hTargetProcessHandle: Process.GetCurrentProcess().SafeHandle,
            //                     lpTargetHandle: out SafeFileHandle lpTargetHandle,
            //                     dwDesiredAccess: default,
            //                     bInheritHandle: true,
            //                     dwOptions: DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS))
            // { }

            //* Query the object type */
            // string typeName;
            // PUBLIC_OBJECT_TYPE_INFORMATION* objectTypeInfo = (PUBLIC_OBJECT_TYPE_INFORMATION*)Marshal.AllocHGlobal(sizeof(PUBLIC_OBJECT_TYPE_INFORMATION));
            // uint* returnLength = (uint*)Marshal.AllocHGlobal(sizeof(uint));
            // NTSTATUS status;

            // if ((status = NtQueryObject(HandleValue, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, objectTypeInfo, (uint)sizeof(PUBLIC_OBJECT_TYPE_INFORMATION), returnLength)).Severity == NTSTATUS.SeverityCode.STATUS_SEVERITY_SUCCESS)
            // {
            //     typeName = objectTypeInfo->TypeName.ToStringLength();
            //     Marshal.FreeHGlobal((IntPtr)objectTypeInfo);
            // }
            // else
            // {
            //     Marshal.FreeHGlobal((IntPtr)objectTypeInfo);
            //     throw new Exception("P/Invoke function NtQueryObject failed. See Exception data.", new NTStatusException(status));
            // }

            // return typeName;
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

    private sealed class ObjectTypesInformationBuffer : IDisposable
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
        public static unsafe ObjectTypesInformationBuffer PhEnumObjectTypes()
        {
            NTSTATUS status;
            ObjectTypesInformationBuffer buffer;
            uint returnLength;

            buffer = new(0x1000);

            while ((status = NtQueryObject(
                null,
                OBJECT_INFORMATION_CLASS.ObjectTypesInformation,
                (void*)buffer.pointer,
                buffer.bytes,
                &returnLength
                )) == Code.STATUS_INFO_LENGTH_MISMATCH)
            {
                // Fail if we're resizing the buffer to something very large.
                if (returnLength * 1.5 > PH_LARGE_BUFFER_SIZE)
                    throw new PInvoke.NTStatusException(Code.STATUS_INSUFFICIENT_RESOURCES);

                buffer.ReAllocate((uint)(returnLength * 1.5));
            }

            status.ThrowOnError();

            return buffer;
        }

        public unsafe uint PhGetObjectTypeNumber(string typeName)
        {
            OBJECT_TYPE_INFORMATION* objectType;
            uint objectIndex = uint.MaxValue;
            uint i;

            if (NumberOfTypes != default)
            {
                objectType = PH_FIRST_OBJECT_TYPE((void*)pointer);

                for (i = 0; i < NumberOfTypes; i++)
                {
                    string typeNameSr = (string)objectType->TypeName;

                    if (string.Equals(typeNameSr, typeName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (Environment.OSVersion.Platform == PlatformID.Win32NT && Environment.OSVersion.Version >= new Version(6, 3))
                        {
                            objectIndex = objectType->TypeIndex;
                            break;
                        }
                        else
                        {
                            objectIndex = i + 2;
                            break;
                        }
                    }

                    objectType = PH_NEXT_OBJECT_TYPE(objectType);
                }
            }

            return objectIndex;
        }

        public unsafe string? PhGetObjectTypeName(uint TypeIndex)
        {
            OBJECT_TYPE_INFORMATION* objectType;
            string? objectTypeName = null;
            uint i;

            objectType = PH_FIRST_OBJECT_TYPE((void*)pointer);

            for (i = 0; i < NumberOfTypes; i++)
            {
                if (OperatingSystem.IsWindowsVersionAtLeast(6, 2))
                {
                    if (TypeIndex == objectType->TypeIndex)
                    {
                        objectTypeName = (string)objectType->TypeName;
                        break;
                    }
                }
                else
                {
                    if (TypeIndex == (i + 2))
                    {
                        objectTypeName = (string)objectType->TypeName;
                        break;
                    }
                }

                objectType = PH_NEXT_OBJECT_TYPE(objectType);
            }

            return objectTypeName;
        }
    }

    public static unsafe OBJECT_TYPE_INFORMATION* PH_FIRST_OBJECT_TYPE(void* ObjectTypes) => (OBJECT_TYPE_INFORMATION*)PTR_ADD_OFFSET(ObjectTypes, ALIGN_UP((nuint)sizeof(OBJECT_TYPES_INFORMATION), typeof(UIntPtr)));
    public static unsafe OBJECT_TYPE_INFORMATION* PH_NEXT_OBJECT_TYPE(OBJECT_TYPE_INFORMATION* ObjectType) => (OBJECT_TYPE_INFORMATION*)PTR_ADD_OFFSET(ObjectType, (nuint)Marshal.SizeOf<OBJECT_TYPE_INFORMATION>() + ALIGN_UP(ObjectType->TypeName.MaximumLength, typeof(UIntPtr)));
    public static unsafe void* PTR_ADD_OFFSET(void* Pointer, nuint Offset) => (void*)((nuint)Pointer + Offset);
    public static nuint ALIGN_UP(nuint Address, Type type) => ALIGN_UP_BY(Address, (uint)Marshal.SizeOf(type));
    public static nuint ALIGN_UP_BY(nuint Address, uint Align) => (Address + Align - 1) & ~(Align - 1);
}
