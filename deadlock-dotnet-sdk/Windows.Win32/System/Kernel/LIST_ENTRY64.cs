namespace Windows.Win32.System.Kernel;

/// <inheritdoc cref="LIST_ENTRY"/>
internal struct LIST_ENTRY64<T> where T : unmanaged
{
    /// <summary>
    /// <para>For a <b>LIST_ENTRY</b> structure that serves as a list entry, the <b>Flink</b> member points to the next entry in the list or to the list header if there is no next entry in the list. For a <b>LIST_ENTRY</b> structure that serves as the list header, the <b>Flink</b> member points to the first entry in the list or to the LIST_ENTRY structure itself if the list is empty.</para>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//ntdef/ns-ntdef-list_entry#members">Read more on docs.microsoft.com</see>.</para>
    /// </summary>
    /// <remarks>Points to a LIST_ENTRY64</remarks>
    /// <summary>
    /// <para>For a <b>LIST_ENTRY</b> structure that serves as a list entry, the <b>Blink</b> member points to the previous entry in the list or to the list header if there is no previous entry in the list. For a <b>LIST_ENTRY</b> structure that serves as the list header, the <b>Blink</b> member points to the last entry in the list or to the <b>LIST_ENTRY</b> structure itself if the list is empty.</para>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//ntdef/ns-ntdef-list_entry#members">Read more on docs.microsoft.com</see>.</para>
    /// </summary>
    internal unsafe UIntPtr64<LIST_ENTRY64<T>> Blink;
}

/// <inheritdoc cref="LIST_ENTRY"/>
internal struct LIST_ENTRY64
{
    /// <summary>
    /// <para>For a <b>LIST_ENTRY</b> structure that serves as a list entry, the <b>Flink</b> member points to the next entry in the list or to the list header if there is no next entry in the list. For a <b>LIST_ENTRY</b> structure that serves as the list header, the <b>Flink</b> member points to the first entry in the list or to the LIST_ENTRY structure itself if the list is empty.</para>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//ntdef/ns-ntdef-list_entry#members">Read more on docs.microsoft.com</see>.</para>
    /// </summary>
    internal unsafe UIntPtr64<LIST_ENTRY64> Flink;
    /// <summary>
    /// <para>For a <b>LIST_ENTRY</b> structure that serves as a list entry, the <b>Blink</b> member points to the previous entry in the list or to the list header if there is no previous entry in the list. For a <b>LIST_ENTRY</b> structure that serves as the list header, the <b>Blink</b> member points to the last entry in the list or to the <b>LIST_ENTRY</b> structure itself if the list is empty.</para>
    /// <para><see href="https://docs.microsoft.com/windows/win32/api//ntdef/ns-ntdef-list_entry#members">Read more on docs.microsoft.com</see>.</para>
    /// </summary>
    internal unsafe UIntPtr64<LIST_ENTRY64> Blink;
}
