using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PInvoke;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Threading;
using Windows.Win32.System.WindowsProgramming;
using static System.Environment;
using static Windows.Win32.PInvoke;
using static Windows.Win32.PS_PROTECTION.PS_PROTECTED_TYPE;
using Code = PInvoke.NTSTATUS.Code;
using NTSTATUS = Windows.Win32.Foundation.NTSTATUS;
using Win32Exception = System.ComponentModel.Win32Exception;

namespace deadlock_dotnet_sdk.Domain;

public partial class ProcessInfo
{
    private bool canGetQueryLimitedInfoHandle;
    private bool canGetReadMemoryHandle;
    private (ProcessQueryHandle? v, Exception? ex) processHandle;

    public ProcessInfo(Process process)
    {
        Process = process;
    }

    /// <summary>The base Process object this instance expands upon.</summary>
    public Process Process { get; }
    public int ProcessId => Process.Id;

    public (ProcessQueryHandle? v, Exception? ex) ProcessHandle
    {
        get
        {
            if (processHandle == default)
            {
                const string exMsg = "Unable to open handle; ";
                // We can't lookup the ProcessProtection without opening a process handle to check the process protection.
                //PROCESS_ACCESS_RIGHTS access = ProcessProtection.v?.Type is PS_PROTECTION.PS_PROTECTED_TYPE.PsProtectedTypeProtected ? PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ;

                try
                {
                    return processHandle = (ProcessQueryHandle.OpenProcessHandle(
                            ProcessId,
                            PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ),
                        null);
                }
                catch (Win32Exception ex) when ((Win32ErrorCode)ex.NativeErrorCode is Win32ErrorCode.ERROR_ACCESS_DENIED)
                {
                    // Before assuming anything, try without PROCESS_VM_READ. Without it, we don't need Debug privilege, but the PEB and all of its recursive members (e.g. Command Line) will be unavailable.
                    const string exAccessMsg = exMsg + " The requested permissions were denied.";
                    string exPermsFirst = NewLine + "First attempt's requested permissions: " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION) + ", " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ);
                    canGetReadMemoryHandle = false;

                    try
                    {
                        return processHandle = (ProcessQueryHandle.OpenProcessHandle(ProcessId, PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION), null);
                    }
                    catch (Win32Exception ex2) when ((Win32ErrorCode)ex.NativeErrorCode is Win32ErrorCode.ERROR_ACCESS_DENIED)
                    {
                        // Debug Mode could not be enabled? Was SE_DEBUG_NAME denied to user or is current process not elevated?
                        canGetQueryLimitedInfoHandle = false;
                        string exPermsSecond = NewLine + "Second attempt's requested permissions: " + nameof(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION);
                        return (null, new UnauthorizedAccessException(exAccessMsg + exPermsFirst + exPermsSecond, ex2));
                    }
                    catch (Exception ex2)
                    {
                        canGetQueryLimitedInfoHandle = false;
                        return (null, new AggregateException(exMsg + " Permissions were denied and an unknown error occurred.", new Exception[] { ex, ex2 }));
                    }
                }
                catch (Win32Exception ex) when ((Win32ErrorCode)ex.NativeErrorCode is Win32ErrorCode.ERROR_INVALID_PARAMETER)
                {
                    return (null, new ArgumentException(exMsg + " A process with ID " + ProcessId + " could not be found. The process may have exited.", ex));
                }
                catch (Exception ex)
                {
                    // unknown error
                    return (null, new Exception(exMsg + " An unknown error occurred.", ex));
                }
            }
            else
            {
                return processHandle;
            }
        }
    }
}
