namespace Windows.Win32;

/// <summary>
/// The <see href="https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/handle_ex.htm"><c>SYSTEM_HANDLE_INFORMATION_EX</c></see>
/// struct is 0x24 or 0x38 bytes in 32-bit and 64-bit Windows, respectively. However, Handles is a variable-length array.
/// </summary>
public readonly unsafe struct SYSTEM_HANDLE_INFORMATION_EX
{
#pragma warning disable CS0649

    /// <summary>
    /// As documented unofficially, NumberOfHandles is a 4-byte or 8-byte ULONG_PTR in 32-bit and 64-bit Windows, respectively.<br/>
    /// This is not to be confused with uint* or ulong*.
    /// </summary>
    public readonly UIntPtr NumberOfHandles;
    public readonly UIntPtr Reserved;
    public readonly SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handle_0;

    /// <summary>
    /// If IsEmpty is true, AsSpan() failed.
    /// </summary>
    /// <value></value>
    public ReadOnlySpan<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> AsReadOnlySpan
    {
        get
        {
            try
            {
                return AsSpan();
            }
            catch (Exception)
            {
                return ReadOnlySpan<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>.Empty;
            }
        }
    }
#pragma warning restore CS0649

    /// <summary>
    /// Infer an array from the address of Handle_0 and NumberOfHandles, then return it as a ReadOnlySpan
    /// </summary>
    /// <exception cref="ArgumentException"/>
    /// <exception cref="ArgumentOutOfRangeException"/>
    public ReadOnlySpan<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> AsSpan()
    {
        fixed (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* pHandle_0 = &Handle_0)
            return new ReadOnlySpan<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(pHandle_0, (int)NumberOfHandles).ToArray();
    }

    /// <summary>
    /// DEBUGGING | Test for memory access. System.AccessViolationException due to these values being in a protected memory range is a problem.
    /// </summary>
    internal void CheckAccess()
    {
        var tmp = AsSpan();

        var lastItem = tmp[(int)NumberOfHandles - 1];

        Console.WriteLine(lastItem + ": " + lastItem.UniqueProcessId);
    }

    public static explicit operator ReadOnlySpan<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(SYSTEM_HANDLE_INFORMATION_EX value) => value.AsSpan();
}
