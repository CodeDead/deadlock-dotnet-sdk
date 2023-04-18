using System.Diagnostics;
using static System.Environment;
namespace deadlock_dotnet_sdk.Domain;

public sealed class ProcessList : List<ProcessInfo>
{
    public ProcessList() { }
    public ProcessList(IEnumerable<ProcessInfo> collection) : base(collection)
    { }

    public ProcessList(int capacity) : base(capacity)
    { }

    /// <summary>
    /// Find a ProcessInfo by its process ID and returns it. If no existing ProcessInfo is found, the system is queried for a Process with that ID. If the returned Process is not null, it is returned as a ProcessInfo object.
    /// </summary>
    /// <param name="processId">The process ID of the process to find.</param>
    /// <returns>The existing ProcessInfo object with an ID matching <paramref name="processId"/>. If it does not exist yet, the system is queried for a Process with that ID. If the returned Process is not null, it is returned as a ProcessInfo object.</returns>
    public ProcessInfo GetProcessById(int processId)
    {
        var result = Find(p => p.Process?.Id == processId);
        if (result is not null)
            return result;

        ProcessInfo pi;

        try
        {
            var p = Process.GetProcessById(processId);

            if (p is null)
            {
                pi = new ProcessInfo(processId);
                Add(pi);
                return pi;
            }

            pi = new(p);
            Add(pi);
            return pi;
        }
        catch (ArgumentException ex) // 
        {
            Trace.WriteLine($"No process was found with ID {processId}. If it *did* exist, the process had exited and is not in .NET's internal process list." + NewLine + ex.ToString(), "ERROR");
            pi = new ProcessInfo(processId);
            Add(pi);
            return pi;
        }
        catch (Exception ex)
        {
            Trace.WriteLine("An unknown exception was thrown." + NewLine + ex, "ERROR");
            pi = new ProcessInfo(processId);
            Add(pi);
            return pi;
        }
    }
}
