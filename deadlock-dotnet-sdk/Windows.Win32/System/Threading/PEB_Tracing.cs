namespace Windows.Win32.System.Threading;

[Flags]
internal enum PEB_Tracing : uint
{
    /// <summary>Compatibility: 6.1 and higher</summary>
    HeapTracingEnabled = 1,
    /// <summary>Compatibility: 6.1 and higher</summary>
    CritSecTracingEnabled = 1 << 1,
    /// <summary>Compatibility: 6.2 and higher</summary>
    LibLoaderTracingEnabled = 1 << 2,
}
