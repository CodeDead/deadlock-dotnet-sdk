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

        /// <summary>
        /// Initialize a new RmListException
        /// </summary>
        /// <param name="message">The error message</param>
        public RmListException(string message) : base(message)
        {
            // Default constructor
        }
    }
}
