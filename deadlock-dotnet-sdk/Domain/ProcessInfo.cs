using System.Diagnostics;

namespace deadlock_dotnet_sdk.Domain;

public class ProcessInfo
{
    public ProcessInfo(Process process)
    {
        Process = process;
    }

    public Process Process { get; }
    public List<SafeHandleEx> Handles { get; set; } = new();
}
