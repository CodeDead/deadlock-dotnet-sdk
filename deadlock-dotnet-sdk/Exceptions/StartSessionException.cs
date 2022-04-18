namespace deadlock_dotnet_sdk.Exceptions
{
    public class StartSessionException : Exception
    {
        /// <summary>
        /// Initialize a new StartSessionException
        /// </summary>
        public StartSessionException()
        {
            // Default constructor
        }

        /// <summary>
        /// Initialize a new StartSessionException
        /// </summary>
        /// <param name="message">The error message</param>
        public StartSessionException(string message) : base(message)
        {
            // Default constructor
        }
    }
}
