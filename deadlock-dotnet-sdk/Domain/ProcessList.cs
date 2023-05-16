using System.Collections;
using System.Diagnostics;
using static System.Environment;
namespace deadlock_dotnet_sdk.Domain;

public sealed class ProcessList : IList<ProcessInfo>
{
    private readonly List<ProcessInfo> value;

    public ProcessList() { value = new(); }
    public ProcessList(List<ProcessInfo> list) => value = list;
    public ProcessList(IEnumerable<ProcessInfo> collection) => value = new(collection);
    public ProcessList(int capacity) => value = new(capacity);

    #region IList implementation
    public ProcessInfo this[int index] { get => value[index]; set => this.value[index] = value; }
    public int Count => value.Count;
    public bool IsReadOnly => ((ICollection<ProcessInfo>)value).IsReadOnly;
    public void Add(ProcessInfo item) => value.Add(item);
    public void Clear() => value.Clear();
    public bool Contains(ProcessInfo item) => value.Contains(item);
    public void CopyTo(ProcessInfo[] array, int arrayIndex) => value.CopyTo(array, arrayIndex);
    public IEnumerator<ProcessInfo> GetEnumerator() => ((IEnumerable<ProcessInfo>)value).GetEnumerator();
    public int IndexOf(ProcessInfo item) => value.IndexOf(item);
    public void Insert(int index, ProcessInfo item) => value.Insert(index, item);
    public bool Remove(ProcessInfo item) => value.Remove(item);
    public void RemoveAt(int index) => value.RemoveAt(index);
    IEnumerator IEnumerable.GetEnumerator() => ((IEnumerable)value).GetEnumerator();
    #endregion IList implementation

    /// <summary>
    /// Find a ProcessInfo by its process ID and returns it. If no existing ProcessInfo is found, the system is queried for a Process with that ID. If the returned Process is not null, it is returned as a ProcessInfo object.
    /// </summary>
    /// <param name="processId">The process ID of the process to find.</param>
    /// <returns>The existing ProcessInfo object with an ID matching <paramref name="processId"/>. If it does not exist yet, the system is queried for a Process with that ID. If the returned Process is not null, it is returned as a ProcessInfo object.</returns>
    public ProcessInfo GetProcessById(int processId)
    {
        var result = value.Find(p => p.Process?.Id == processId);
        if (result is not null)
            return result;

        ProcessInfo pi;

        try
        {
            pi = new(Process.GetProcessById(processId));
            Add(pi);
            return pi;
        }
        catch (ArgumentException ex) // 
        {
            Trace.TraceError($"No process was found with ID {processId}. If it *did* exist, the process had exited and is not in .NET's internal process list." + "\r\n" + ex.ToString());
            pi = new ProcessInfo(processId);
            Add(pi);
            return pi;
        }
        catch (Exception ex)
        {
            Trace.TraceError("An unknown exception was thrown.\r\n" + ex);
            pi = new ProcessInfo(processId);
            Add(pi);
            return pi;
        }
    }

    public static explicit operator ProcessList(List<ProcessInfo> v) => new(v);
}
