using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32.Foundation;
using Windows.Win32.System.Kernel;
using Code = PInvoke.NTSTATUS.Code;
using Env = System.Environment;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;

namespace Windows.Win32.System.Threading;

public partial class ProcessEnvironmentBlock
{
    internal unsafe ProcessEnvironmentBlock(PEB32 peb32)
    {
        ActivationContextData = (peb32.ActivationContextData, null);
        ActiveProcessAffinityMask = (peb32.ActiveProcessAffinityMask, null);
        AnsiCodePageData = (peb32.AnsiCodePageData, null);
        ApiSetMap = (peb32.ApiSetMap, null);
        AppCompatFlags = peb32.AppCompatFlags;
        AppCompatFlagsUser = peb32.AppCompatFlagsUser;
        AppCompatInfo = (peb32.AppCompatInfo, null);
        AtlThunkSListPtr = (peb32.AtlThunkSListPtr, null);
        AtlThunkSListPtr32 = (peb32.AtlThunkSListPtr32, null);
        BeingDebugged = peb32.BeingDebugged;
        BitField = peb32.BitField;
        CloudFileDiagFlags = peb32.CloudFileDiagFlags;
        CloudFileFlags = peb32.CloudFileFlags;
        CriticalSectionTimeout = peb32.CriticalSectionTimeout;
        CrossProcessFlags = peb32.CrossProcessFlags;
        CSDVersion = (peb32.CSDVersion, null);
        CsrServerReadOnlySharedMemoryBase = peb32.CsrServerReadOnlySharedMemoryBase;
        FastPebLock = (peb32.FastPebLock, null);
        FlatListHead = (peb32.FlatListHead, null);
        FlsBitmap = (peb32.FlsBitmap, null);
        FlsBitmapBits = peb32.FlsBitmapBits_Safe;
        FlsCallback = (peb32.FlsCallback, null);
        FlsHighIndex = peb32.FlsHighIndex;
        GdiDCAttributeList = peb32.GdiDCAttributeList;
        GdiHandleBuffer = peb32.GdiHandleBuffer_Safe;
        GdiSharedHandleTable = (peb32.GdiSharedHandleTable, null);
        HeapDeCommitFreeBlockThreshold = (peb32.HeapDeCommitFreeBlockThreshold, null);
        HeapDeCommitTotalFreeThreshold = (peb32.HeapDeCommitTotalFreeThreshold, null);
        HeapSegmentCommit = (peb32.HeapSegmentCommit, null);
        HeapSegmentReserve = (peb32.HeapSegmentReserve, null);
        IFEOKey = (peb32.IFEOKey, null);
        ImageBaseAddress = (peb32.ImageBaseAddress, null);
        ImageSubsystem = peb32.ImageSubsystem;
        ImageSubsystemMajorVersion = peb32.ImageSubsystemMajorVersion;
        ImageSubsystemMinorVersion = peb32.ImageSubsystemMinorVersion;
        InheritedAddressSpace = peb32.InheritedAddressSpace;
        KernelCallBackTable = (peb32.KernelCallBackTable, null);
        Ldr = (peb32.Ldr, null);
        LeapSecondData = (peb32.LeapSecondData, null);
        LeapSecondFlags = peb32.LeapSecondFlags;
        LoaderLock = (peb32.LoaderLock, null);
        MaximumNumberOfHeaps = peb32.MaximumNumberOfHeaps;
        MinimumStackCommit = (peb32.MinimumStackCommit, null);
        Mutant = (peb32.Mutant, null);
        NtGlobalFlag = peb32.NtGlobalFlag;
        NtGlobalFlag2 = peb32.NtGlobalFlag2;
        NumberOfHeaps = peb32.NumberOfHeaps;
        NumberOfProcessors = peb32.NumberOfProcessors;
        OemCodePageData = (peb32.OemCodePageData, null);
        OSBuildNumber = peb32.OSBuildNumber;
        OSCSDVersion = peb32.OSCSDVersion;
        OSMajorVersion = peb32.OSMajorVersion;
        OSMinorVersion = peb32.OSMinorVersion;
        OSPlatformId = peb32.OSPlatformId;
        pContextData = (peb32.pContextData, null);
        pImageHeaderHash = (peb32.pImageHeaderHash, null);
        PlaceholderCompatibilityMode = peb32.PlaceholderCompatibilityMode;
        PostProcessInitRoutine = (peb32.PostProcessInitRoutine, null);
        ProcessAssemblyStorageMap = (peb32.ProcessAssemblyStorageMap, null);
        ProcessHeap = (peb32.ProcessHeap, null);
        ProcessHeaps = (peb32.ProcessHeaps, null);
        ProcessParameters = (peb32.ProcessParameters, null);
        ProcessTarterHelper = (peb32.ProcessTarterHelper, null);
        pShimData = (peb32.pShimData, null);
        ReadImageFileExecOptions = peb32.ReadImageFileExecOptions;
        ReadOnlySharedMemoryBase = (peb32.ReadOnlySharedMemoryBase, null);
        ReadOnlyStaticServerData = (peb32.ReadOnlyStaticServerData, null);
        SessionId = peb32.SessionId;
        SharedData = (peb32.SharedData, null);
        SubSystemData = (peb32.SubSystemData, null);
        SystemAssemblyStorageMap = (peb32.SystemAssemblyStorageMap, null);
        SystemDefaultActivationContextData = (peb32.SystemDefaultActivationContextData, null);
        TelemetryCoverageHeader = (peb32.TelemetryCoverageHeader, null);
        TlsBitmap = (peb32.TlsBitmap, null);
        TlsBitmapBits = new(peb32.TlsBitmapBits_Safe);
        TlsExpansionBitmap = (peb32.TlsExpansionBitmap, null);
        TlsExpansionBitmapBits = peb32.TlsExpansionBitmapBits_Safe;
        TlsExpansionCounter = peb32.TlsExpansionCounter;
        TppWorkerList = (peb32.TppWorkerList, null);
        TppWorkerpListLock = peb32.TppWorkerpListLock;
        TracingFlags = peb32.TracingFlags;
        UnicodeCaseTableData = (peb32.UnicodeCaseTableData, null);
        UserSharedInfoPtr = (peb32.UserSharedInfoPtr, null);
        WaitOnAddressHashTable = ((UIntPtr32[])peb32.WaitOnAddressHashTable_Safe.Cast<UIntPtr32>(), null);
        WerRegistrationData = (peb32.WerRegistrationData, null);
        WerShipAssertPtr = (peb32.WerShipAssertPtr, null);
    }

    internal unsafe ProcessEnvironmentBlock(PEB64 peb64)
    {
        ActivationContextData = (null, peb64.ActivationContextData);
        ActiveProcessAffinityMask = (null, peb64.ActiveProcessAffinityMask);
        AnsiCodePageData = (null, peb64.AnsiCodePageData);
        ApiSetMap = (null, peb64.ApiSetMap);
        AppCompatFlags = peb64.AppCompatFlags;
        AppCompatFlagsUser = peb64.AppCompatFlagsUser;
        AppCompatInfo = (null, peb64.AppCompatInfo);
        AtlThunkSListPtr = (null, peb64.AtlThunkSListPtr);
        AtlThunkSListPtr32 = (null, peb64.AtlThunkSListPtr32);
        BeingDebugged = peb64.BeingDebugged;
        BitField = peb64.BitField;
        CloudFileDiagFlags = peb64.CloudFileDiagFlags;
        CloudFileFlags = peb64.CloudFileFlags;
        CriticalSectionTimeout = peb64.CriticalSectionTimeout;
        CrossProcessFlags = peb64.CrossProcessFlags;
        CSDVersion = (null, peb64.CSDVersion);
        CsrServerReadOnlySharedMemoryBase = peb64.CsrServerReadOnlySharedMemoryBase;
        FastPebLock = (null, peb64.FastPebLock);
        FlatListHead = (null, peb64.FlatListHead);
        FlsBitmap = (null, peb64.FlsBitmap);
        FlsBitmapBits = peb64.FlsBitmapBits_Safe;
        FlsCallback = (null, peb64.FlsCallback);
        FlsHighIndex = peb64.FlsHighIndex;
        GdiDCAttributeList = peb64.GdiDCAttributeList;
        GdiHandleBuffer = peb64.GdiHandleBuffer_Safe;
        GdiSharedHandleTable = (null, peb64.GdiSharedHandleTable);
        HeapDeCommitFreeBlockThreshold = (null, peb64.HeapDeCommitFreeBlockThreshold);
        HeapDeCommitTotalFreeThreshold = (null, peb64.HeapDeCommitTotalFreeThreshold);
        HeapSegmentCommit = (null, peb64.HeapSegmentCommit);
        HeapSegmentReserve = (null, peb64.HeapSegmentReserve);
        IFEOKey = (null, peb64.IFEOKey);
        ImageBaseAddress = (null, peb64.ImageBaseAddress);
        ImageSubsystem = peb64.ImageSubsystem;
        ImageSubsystemMajorVersion = peb64.ImageSubsystemMajorVersion;
        ImageSubsystemMinorVersion = peb64.ImageSubsystemMinorVersion;
        InheritedAddressSpace = peb64.InheritedAddressSpace;
        KernelCallBackTable = (null, peb64.KernelCallBackTable);
        Ldr = (null, peb64.Ldr);
        LeapSecondData = (null, peb64.LeapSecondData);
        LeapSecondFlags = peb64.LeapSecondFlags;
        LoaderLock = (null, peb64.LoaderLock);
        MaximumNumberOfHeaps = peb64.MaximumNumberOfHeaps;
        MinimumStackCommit = (null, peb64.MinimumStackCommit);
        Mutant = (null, peb64.Mutant);
        NtGlobalFlag = peb64.NtGlobalFlag;
        NtGlobalFlag2 = peb64.NtGlobalFlag2;
        NumberOfHeaps = peb64.NumberOfHeaps;
        NumberOfProcessors = peb64.NumberOfProcessors;
        OemCodePageData = (null, peb64.OemCodePageData);
        OSBuildNumber = peb64.OSBuildNumber;
        OSCSDVersion = peb64.OSCSDVersion;
        OSMajorVersion = peb64.OSMajorVersion;
        OSMinorVersion = peb64.OSMinorVersion;
        OSPlatformId = peb64.OSPlatformId;
        pContextData = (null, peb64.pContextData);
        pImageHeaderHash = (null, peb64.pImageHeaderHash);
        PlaceholderCompatibilityMode = peb64.PlaceholderCompatibilityMode;
        PostProcessInitRoutine = (null, peb64.PostProcessInitRoutine);
        ProcessAssemblyStorageMap = (null, peb64.ProcessAssemblyStorageMap);
        ProcessHeap = (null, peb64.ProcessHeap);
        ProcessHeaps = (null, peb64.ProcessHeaps);
        ProcessParameters = (null, peb64.ProcessParameters);
        ProcessTarterHelper = (null, peb64.ProcessTarterHelper);
        pShimData = (null, peb64.pShimData);
        ReadImageFileExecOptions = peb64.ReadImageFileExecOptions;
        ReadOnlySharedMemoryBase = (null, peb64.ReadOnlySharedMemoryBase);
        ReadOnlyStaticServerData = (null, peb64.ReadOnlyStaticServerData);
        SessionId = peb64.SessionId;
        SharedData = (null, peb64.SharedData);
        SubSystemData = (null, peb64.SubSystemData);
        SystemAssemblyStorageMap = (null, peb64.SystemAssemblyStorageMap);
        SystemDefaultActivationContextData = (null, peb64.SystemDefaultActivationContextData);
        TelemetryCoverageHeader = (null, peb64.TelemetryCoverageHeader);
        TlsBitmap = (null, peb64.TlsBitmap);
        TlsBitmapBits = new(peb64.TlsBitmapBits_Safe);
        TlsExpansionBitmap = (null, peb64.TlsExpansionBitmap);
        TlsExpansionBitmapBits = peb64.TlsExpansionBitmapBits_Safe;
        TlsExpansionCounter = peb64.TlsExpansionCounter;
        TppWorkerList = (null, peb64.TppWorkerList);
        TppWorkerpListLock = peb64.TppWorkerpListLock;
        TracingFlags = peb64.TracingFlags;
        UnicodeCaseTableData = (null, peb64.UnicodeCaseTableData);
        UserSharedInfoPtr = (null, peb64.UserSharedInfoPtr);
        WaitOnAddressHashTable = (null, peb64.WaitOnAddressHashTable_Safe.Cast<UIntPtr64>().ToArray());
        WerRegistrationData = (null, peb64.WerRegistrationData);
        WerShipAssertPtr = (null, peb64.WerShipAssertPtr);
    }

    #region INITIAL_PEB
    /// <summary>Compatibility: all</summary>
    internal readonly BOOLEAN InheritedAddressSpace;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly BOOLEAN ReadImageFileExecOptions;
    /// <summary>
    /// Indicates whether the specified process is currently being debugged. The <b>PEB</b> structure, however, is an internal operating-system structure whose layout may change in the future. It is best to use the <a href="https://docs.microsoft.com/windows/desktop/api/debugapi/nf-debugapi-checkremotedebuggerpresent">CheckRemoteDebuggerPresent</a> function instead.<br/>
    /// Compatibility: 3.51 and higher
    /// </summary>
    internal readonly BOOLEAN BeingDebugged;
    public bool IsBeingDebugged => BeingDebugged;
    /// <summary>Compatibility: late 5.2 and higher</summary>
    internal readonly PEB_BitField BitField;
    /// <summary>Compatibility: all</summary>
    internal readonly (HANDLE32? w32, HANDLE64? w64) Mutant;
    #endregion INITIAL_PEB

    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) ImageBaseAddress;
    /// <summary>Compatibility: all<br/>
    /// A pointer to a <a href="https://docs.microsoft.com/windows/desktop/api/winternl/ns-winternl-peb_ldr_data">PEB_LDR_DATA</a> structure that contains information about the loaded modules for the process.</summary>
    internal readonly unsafe (UIntPtr32<PEB_LDR_DATA32>? w32, UIntPtr64<PEB_LDR_DATA64>? w64) Ldr;

    /// <summary>
    /// Pass a SafeProcessHandle with PROCESS_VM_READ to copy the process's LoaderData from its memory.
    /// </summary>
    /// <param name="processHandle">A SafeProcessHandle opened with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ"/>. </param>
    /// <returns>An instance of the LoaderData class, wrapping the target process's 32-bit or 64-bit PEB_LDR_DATA.</returns>
    /// <exception cref="NullReferenceException">Unable to get Loader data; The pointers for the 32-bit and 64-bit data are both null.</exception>
    /// <exception cref="AccessViolationException">Failed to get Loader data; The process attempted to read protected memory.</exception>
    /// <exception cref="Exception">Failed to get Loader data. An unknown error occurred. See Message and/or InnerException for details.</exception>
    public unsafe LoaderData GetPEBLoaderData(SafeProcessHandle processHandle)
    {
        const string unableMsg = "Unable to get Loader data; ";
        const string failedMsg = "Failed to get Loader data; ";
        const string protectedMemMsg = "The process attempted to read protected memory.";

        if (Ldr is (null, null))
            throw new NullReferenceException(unableMsg + "The pointers for the 32-bit and 64-bit data are both null.");

        if (!Env.Is64BitProcess && Ldr.w64 is not null)
        {
            using SafeBuffer<PEB_LDR_DATA64> buffer = new(numElements: 2); // We need one + extra space for trailing data
            ulong bytesRead;
            NTSTATUS status;

            if ((status = PInvoke.NtWow64ReadVirtualMemory64(processHandle, (UIntPtr64)Ldr.w64, (void*)buffer.DangerousGetHandle(), buffer.ByteLength, &bytesRead)).Code is Code.STATUS_SUCCESS)
                return new(buffer.Read<PEB_LDR_DATA64>(0));

            if (status.Code is Code.STATUS_PARTIAL_COPY)
                throw new AccessViolationException(failedMsg + protectedMemMsg, new NTStatusException(status));
            else
                throw new Exception(failedMsg + status.Message, new NTStatusException(status));
        }
        else
        {
            nuint bytesRead;

            if (Ldr.w32 is not null)
            {
                using SafeBuffer<PEB_LDR_DATA32> buffer = new(numElements: 2); // We need one + extra space for trailing data

                if (PInvoke.ReadProcessMemory(processHandle, (void*)Ldr.w32, (void*)buffer.DangerousGetHandle(), (nuint)buffer.ByteLength, &bytesRead))
                    return new(buffer.Read<PEB_LDR_DATA32>(0));
                // else, jump to `err` declaration
            }
            else if (Ldr.w64 is not null)
            {
                using SafeBuffer<PEB_LDR_DATA64> buffer = new(numElements: 2); // We need one + extra space for trailing data

                if (PInvoke.ReadProcessMemory(processHandle, (void*)Ldr.w64, (void*)buffer.DangerousGetHandle(), (nuint)buffer.ByteLength, &bytesRead))
                    return new(buffer.Read<PEB_LDR_DATA64>(0));
                // else, jump to `err` declaration
            }

            Win32ErrorCode err = (Win32ErrorCode)Marshal.GetLastPInvokeError();
            if (err is Win32ErrorCode.ERROR_PARTIAL_COPY)
                throw new AccessViolationException(failedMsg + protectedMemMsg, new Win32Exception(err));
            else
                throw new Exception(failedMsg + err.GetMessage(), new Win32Exception(err));
        }
    }

    /// <summary>Compatibility: All<br/>
    /// A pointer to an <a href="https://docs.microsoft.com/windows/desktop/api/winternl/ns-winternl-rtl_user_process_parameters">RTL_USER_PROCESS_PARAMETERS</a> structure that contains process parameter information such as the command line.</summary>
    internal readonly unsafe (UIntPtr32<RTL_USER_PROCESS_PARAMETERS32>? w32, UIntPtr64<RTL_USER_PROCESS_PARAMETERS64>? w64) ProcessParameters;

    /// <summary>
    /// Using a SafeProcessHandle with PROCESS_READ_VM access, copy the target process's 32-bit or 64-bit RTL_USER_PROCESS_PARAMETERS data from its memory.
    /// </summary>
    /// <param name="processHandle">A SafeProcessHandle with <see cref="PROCESS_ACCESS_RIGHTS.PROCESS_READ_VM"/> access.</param>
    /// <returns>An instance of <see cref="UserProcessParameters"/> wrapping the process's 32-bit or 64-bit <see cref="RTL_USER_PROCESS_PARAMETERS"/> struct. Refer to <see cref="RTL_USER_PROCESS_PARAMETERS32"/> and <see cref="RTL_USER_PROCESS_PARAMETERS64"/>.</returns>
    /// <exception cref="NullReferenceException">Unable to get Process Parameter data The pointer for the 32-bit and 64-bit data are both null.</exception>
    /// <exception cref="AccessViolationException">Failed to get Process Parameter data; The process attempted to read protected memory.</exception>
    /// <exception cref="Exception">Failed to get Process Parameter data; (native error message)</exception>
    public unsafe UserProcessParameters GetUserProcessParameters(SafeProcessHandle processHandle)
    {
        const string unableMsg = "Unable to get Process Parameter data; ";
        const string failedMsg = "Failed to get Process Parameter data; ";
        const string protectedMemMsg = "The process attempted to read protected memory.";
        const string nullPtrsMsg = "The pointers for the 32-bit and 64-bit data are both null.";

        if (ProcessParameters is (null, null))
            throw new NullReferenceException(unableMsg + nullPtrsMsg);

        if (!Env.Is64BitProcess && Ldr.w64 is not null)
        {
            using SafeBuffer<RTL_USER_PROCESS_PARAMETERS64> buffer = new(numElements: 2); // We need one + extra space for trailing data
            ulong bytesRead;
            NTSTATUS status;

            if ((status = PInvoke.NtWow64ReadVirtualMemory64(processHandle, (UIntPtr64)Ldr.w64, (void*)buffer.DangerousGetHandle(), buffer.ByteLength, &bytesRead)).Code is Code.STATUS_SUCCESS)
                return new(buffer.Read<RTL_USER_PROCESS_PARAMETERS64>(0));

            if (status.Code is Code.STATUS_PARTIAL_COPY)
                throw new AccessViolationException(failedMsg + protectedMemMsg, new NTStatusException(status));
            else
                throw new Exception(failedMsg + status.Message, new NTStatusException(status));
        }
        else
        {
            nuint bytesRead;

            if (Ldr.w32 is not null)
            {
                using SafeBuffer<RTL_USER_PROCESS_PARAMETERS32> buffer = new(numElements: 2); // We need one + extra space for trailing data

                if (PInvoke.ReadProcessMemory(processHandle, (void*)Ldr.w32, (void*)buffer.DangerousGetHandle(), (nuint)buffer.ByteLength, &bytesRead))
                    return new(buffer.Read<RTL_USER_PROCESS_PARAMETERS32>(0));
                // else, jump to `err` declaration
            }
            else if (Ldr.w64 is not null)
            {
                using SafeBuffer<RTL_USER_PROCESS_PARAMETERS64> buffer = new(numElements: 2); // We need one + extra space for trailing data

                if (PInvoke.ReadProcessMemory(processHandle, (void*)Ldr.w64, (void*)buffer.DangerousGetHandle(), (nuint)buffer.ByteLength, &bytesRead))
                    return new(buffer.Read<RTL_USER_PROCESS_PARAMETERS64>(0));
                // else, jump to `err` declaration
            }

            Win32ErrorCode err = (Win32ErrorCode)Marshal.GetLastPInvokeError();
            if (err is Win32ErrorCode.ERROR_PARTIAL_COPY)
                throw new AccessViolationException(failedMsg + protectedMemMsg, new Win32Exception(err));
            else
                throw new Exception(failedMsg + err.GetMessage(), new Win32Exception(err));
        }
    }

    /// <summary>Compatibility: all<br/>
    /// "SubSystem" refers to WoW64, Posix (via PSXDLL.DLL), or WSL. This stores the per-process data for the relevant subsystem.<br/></summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) SubSystemData;
    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) ProcessHeap;

    /// <summary>Compatibility: 5.1 and higher</summary>
    internal readonly (UIntPtr32<RTL_CRITICAL_SECTION32>? w32, UIntPtr64<RTL_CRITICAL_SECTION64>? w64) FastPebLock;
    /// <summary>Compatibility: late 5.2 and higher</summary>
    internal readonly unsafe (UIntPtr32? w32, UIntPtr64? w64) AtlThunkSListPtr;
    /// <summary>Compatibility: 6.0 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) IFEOKey;
    /// <summary>Compatibility: 6.0 and higher</summary>
    internal readonly PEB_CrossProcess CrossProcessFlags;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) KernelCallBackTable;
    /// <summary>Compatibility: 6.0 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) UserSharedInfoPtr;
    /// <summary>Compatibility: late 5.1; 6.1 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) AtlThunkSListPtr32;

    /// <summary>Compatibility: 6.1 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) ApiSetMap;

    /// <summary>Compatibility: all</summary>
    internal readonly uint TlsExpansionCounter;
    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) TlsBitmap;
    /// <summary>Compatibility: all</summary>
    internal readonly TlsBitmapBitsData TlsBitmapBits;
    public readonly struct TlsBitmapBitsData
    {
        /// <summary>
        /// If an array with more than two members is supplied, only the first two members are used.
        /// </summary>
        /// <param name="bitArray">An array of two UInt32 members</param>
        public TlsBitmapBitsData(uint[] bitArray)
        {
            Value0 = bitArray[0];
            Value1 = bitArray[1];
        }

        public readonly uint Value0;
        public readonly uint Value1;

        public static implicit operator uint[](TlsBitmapBitsData v) => new uint[] { v.Value0, v.Value1 };
    }

    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) ReadOnlySharedMemoryBase;
    /// <summary>Compatibility: 1703 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) SharedData;
    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32<UIntPtr32>? w32, UIntPtr64<UIntPtr64>? w64) ReadOnlyStaticServerData;
    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) AnsiCodePageData;
    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) OemCodePageData;
    /// <summary>Compatibility: all</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) UnicodeCaseTableData;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly uint NumberOfProcessors;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly uint NtGlobalFlag;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly long CriticalSectionTimeout;

    #region Appended for Windows NT 3.51
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) HeapSegmentReserve;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) HeapSegmentCommit;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) HeapDeCommitTotalFreeThreshold;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) HeapDeCommitFreeBlockThreshold;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly uint NumberOfHeaps;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly uint MaximumNumberOfHeaps;
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly (UIntPtr32<UIntPtr32>? w32, UIntPtr64<UIntPtr64>? w64) ProcessHeaps;
    #endregion Appended for Windows NT 3.51

    #region Appended for Windows NT 4.0
    /// <summary>Compatibility: 3.51 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) GdiSharedHandleTable;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) ProcessTarterHelper;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly uint GdiDCAttributeList;
    /// <summary>Compatibility: 5.2 and higher</summary>
    internal readonly (UIntPtr32<RTL_CRITICAL_SECTION32>? w32, UIntPtr64<RTL_CRITICAL_SECTION64>? w64) LoaderLock;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly uint OSMajorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly uint OSMinorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly ushort OSBuildNumber;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly ushort OSCSDVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly uint OSPlatformId;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly uint ImageSubsystem;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly uint ImageSubsystemMajorVersion;
    /// <summary>Compatibility: 4.0 and higher</summary>
    internal readonly uint ImageSubsystemMinorVersion;
    /// <summary>Compatibility: late 6.0 and higher</summary>
    internal readonly (KAFFINITY32? w32, KAFFINITY64? w64) ActiveProcessAffinityMask;
    /// <summary>4.0 and higher (x86)</summary>
    internal uint[] GdiHandleBuffer;

    #endregion Appended for Windows NT 4.0

    #region Appended for Windows 2000
    /// <summary>Compatibility: 5.0 and higher<br/>
    /// Not supported. Type: <see cref="PPS_POST_PROCESS_INIT_ROUTINE"/></summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) PostProcessInitRoutine;
    /// <summary>Compatibility: 5.0 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) TlsExpansionBitmap;
    /// <summary>Compatibility: 5.0 and higher</summary>
    internal unsafe uint[] TlsExpansionBitmapBits;
    /// <summary>Compatibility: 5.0 and higher<br/>
    /// The Terminal Services session identifier associated with the current process.</summary>
    /// <remarks>The <see cref="SessionId"/> is one of the two <see cref="PEB"/> members that Microsoft documented when required to disclose use of internal APIs by so-called middleware.</remarks>
    internal readonly uint SessionId;
    /// <summary>Compatibility: 5.1 and higher</summary>
    internal readonly PEB_AppCompat AppCompatFlags;
    /// <summary>Compatibility: 5.1 and higher</summary>
    internal readonly PEB_AppCompat AppCompatFlagsUser;
    /// <summary>Compatibility: 5.1 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) pShimData;
    /// <summary>Compatibility: 5.1 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) AppCompatInfo;
    /// <summary>Compatibility: 5.1 and higher</summary>
    internal readonly (UNICODE_STRING32? w32, UNICODE_STRING64? w64) CSDVersion;
    #endregion Appended for Windows 2000

    #region Appended for Windows XP
    /// <summary>Compatibility: 5.1 and higher<br/>
    /// Type: ACTIVATION_CONTEXT_DATA const * (pointer to a constant ACTIVATION_CONTEXT_DATA)</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) ActivationContextData;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ACTIVATION_CONTEXT_DATA *</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) ProcessAssemblyStorageMap;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ACTIVATION_CONTEXT_DATA const *</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) SystemDefaultActivationContextData;
    /// <summary>Compatibility: 5.1 and higher
    /// Type: ASSEMBLY_STORAGE_MAP *</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) SystemAssemblyStorageMap;
    /// <summary>Compatibility: 5.1 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) MinimumStackCommit;
    #endregion Appended for Windows XP

    #region Appended for Windows Server 2003
    /// <summary>Compatibility: 5.2 to 1809
    /// Type: FLS_CALLBACK_INFO *</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) FlsCallback;
    /// <summary>Compatibility: 5.2 to 1809</summary>
    internal readonly (LIST_ENTRY32? w32, LIST_ENTRY64? w64) FlatListHead; // 5.2 to 1809
    /// <summary>Compatibility: 5.2 to 1809</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) FlsBitmap;
    /// <summary>Compatibility: 5.2 to 1809</summary>
    internal uint[] FlsBitmapBits;
    /// <summary>Compatibility: 5.2 to 1809</summary>
    internal readonly uint FlsHighIndex;
    #endregion Appended for Windows Server 2003

    #region Appended for Windows Vista
    /// <summary>Compatibility: 6.0 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) WerRegistrationData;
    /// <summary>Compatibility: 6.0 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) WerShipAssertPtr;
    #endregion Appended for Windows Vista

    #region Appended for Windows 7
    /// <summary>Compatibility: 6.1 only</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) pContextData;
    /* internal readonly (UIntPtr32? w32, UIntPtr64? w64) pUnused; */
    /// <summary>Compatibility: 6.1 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) pImageHeaderHash;
    internal readonly PEB_Tracing TracingFlags;
    #endregion Appended for Windows 7

    #region Appended for Windows 8
    /// <summary>Compatibility: 6.2 and higher</summary>
    internal readonly ulong CsrServerReadOnlySharedMemoryBase;
    #endregion Appended for Windows 8

    #region Appended Later in Windows 10
    /// <summary>Compatibility: 1511 and higher</summary>
    internal readonly uint TppWorkerpListLock;
    /// <summary>Compatibility: 1511 and higher</summary>
    internal readonly (LIST_ENTRY32? w32, LIST_ENTRY64? w64) TppWorkerList;
    /// <summary>Compatibility: 1511 and higher<br/>
    internal (UIntPtr32[]? w32, UIntPtr64[]? w64) WaitOnAddressHashTable;
    /// <summary>Compatibility: 1709 and higher</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) TelemetryCoverageHeader;
    /// <summary>Compatibility: 1709 and higher</summary>
    internal readonly uint CloudFileFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    internal readonly uint CloudFileDiagFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    internal readonly byte PlaceholderCompatibilityMode;
    /// <summary>Compatibility: 1803 and higher
    /// Type: LEAP_SECOND_DATA *</summary>
    internal readonly (UIntPtr32? w32, UIntPtr64? w64) LeapSecondData;
    internal readonly PEB_LeapSecond LeapSecondFlags;
    /// <summary>Compatibility: 1803 and higher</summary>
    /// <remarks>The <see cref="NtGlobalFlag2"/> member is indeed named for being in some sense an extension of the much older <see cref="NtGlobalFlag"/>.
    ///     Each corresponds to a registry value that can be in either or both of two well-known keys.
    ///     Each also is the name of a variable in the kernel (one exported, the other only internal), which the kernel initializes from the corresponding registry value in the <c>Session Manager</c> key.
    ///     This then provides the initial value for the corresponding <see cref="PEB"/> member, which may then be re-initialized from the same-named registry value in the program's subkey of the <c>Image File Execution Options</c>.<br/><br/>
    /// Only one flag in the new set of them is yet known to be defined.
    ///     A set 0x00000001 bit in the data for the <c>GlobalFlag2</c> registry value becomes a set 0x00000001 bit in the <see cref="NtGlobalFlag2"/> member.
    ///     From there it may set the <see cref="PEB_LeapSecond.SixtySecondEnabled"/> bit in union with the <see cref="LeapSecondFlags"/>.
    ///     The intended effect is that the newly exported <c>RtlpTimeFieldsToTime</c> and <c>RtlpTimeToTimeFields</c> functions become leap-second-aware: when <see cref="LeapSecondData"/> is available, these functions accommodate 60 as the seconds field in a time.<br/><br/>
    /// This support for leap seconds was all new for the 1809 release and thus was also still new, roughly, for the article <see href="https://techcommunity.microsoft.com/t5/networking/blog/leap-seconds-for-the-it-pro-what-you-need-to-know/ba-p/339811">Leap Seconds for the IT Pro: What you need to know</see> at a Microsoft blog dated Feb 14 2019.
    ///     Years later, on 27th January 2023, this is still the only match that Google finds when asked to search microsoft.com for pages that contain <c>GlobalFlag2</c>.
    ///     This is a good example of a trend in what passes as documentation.
    ///     At various levels of Windows administration and programming, it is often that Microsoft's only disclosure of some new feature, large or small, is a blog.
    ///     Administrators and programmers are inevitably grateful that Microsoft employees take the time to blog.
    ///     But let's please not overlook that these blogs are not documentation.
    ///     The helpfulness of Microsoft's employees in explaining new features in fast-moving development, and the readiness of occasionally desperate administrators and programmers to latch on to this help, disguises that Microsoft is systematically skipping the work of documenting these features.</remarks>
    internal readonly uint NtGlobalFlag2;
    #endregion Appended Later in Windows 10
}
