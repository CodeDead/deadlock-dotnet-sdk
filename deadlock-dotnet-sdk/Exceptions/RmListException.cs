namespace deadlock_dotnet_sdk.Exceptions
{
    public class RmListException : Exception
    {
        /// <summary>
        /// Initialize a new RmListException
        /// </summary>
        public RmListException()
        {
            // Default constructor
        }

        public RmListException(string? message) : base(message)
        { }

        public RmListException(string? message, Exception? innerException) : base(message, innerException)
        { }
    }
}
