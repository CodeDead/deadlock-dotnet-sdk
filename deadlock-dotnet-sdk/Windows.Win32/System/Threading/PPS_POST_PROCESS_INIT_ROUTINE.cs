using System.Runtime.InteropServices;

namespace Windows.Win32.System.Threading;

[UnmanagedFunctionPointer(CallingConvention.Winapi)]
internal unsafe delegate void PS_POST_PROCESS_INIT_ROUTINE();

/// <summary>
/// Function Pointer workaround. C# 9's function pointers are only allowed in
/// local scope.
/// </summary>
/// <remarks>
/// The pointer returned by the Marshal methods is typically a "Thunk" rather
/// than a handle. If the .NET runtime sees a thunk was already created, it
/// will re-use that thunk.
/// source: <see href="https://sourcegraph.com/github.com/dotnet/runtime@c92b4176e299c41c0100db91dbd61076f8e52e76/-/blob/src/coreclr/nativeaot/System.Private.CoreLib/src/System/Runtime/InteropServices/PInvokeMarshal.cs?L46:30" />
/// </remarks>
internal struct PPS_POST_PROCESS_INIT_ROUTINE : IEquatable<PPS_POST_PROCESS_INIT_ROUTINE>
{
    public IntPtr Value;

    public PPS_POST_PROCESS_INIT_ROUTINE(PS_POST_PROCESS_INIT_ROUTINE initRoutine)
        => Value = Marshal.GetFunctionPointerForDelegate(initRoutine);

    public static PPS_POST_PROCESS_INIT_ROUTINE FromPointer(IntPtr v)
    {
        try
        {
            _ = Marshal.GetDelegateForFunctionPointer<PS_POST_PROCESS_INIT_ROUTINE>(v); //DevSkim: ignore DS104456 
            return new() { Value = v };
        }
        catch (Exception)
        {
            // not a delegate or open generic type
            // or ptr is null
            return new() { Value = IntPtr.Zero };
        }
    }

    public static explicit operator PPS_POST_PROCESS_INIT_ROUTINE(IntPtr v) => FromPointer(v);

    public bool Equals(PPS_POST_PROCESS_INIT_ROUTINE other) => Value == other.Value;

    public override bool Equals(object? obj)
        => obj is PPS_POST_PROCESS_INIT_ROUTINE pPS_POST_PROCESS_INIT_ROUTINE && Equals(pPS_POST_PROCESS_INIT_ROUTINE);

    public override int GetHashCode() => Value.GetHashCode();
}
