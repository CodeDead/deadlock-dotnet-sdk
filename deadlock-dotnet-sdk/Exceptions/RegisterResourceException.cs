namespace deadlock_dotnet_sdk.Exceptions
{
    public class RegisterResourceException : Exception
    {
        /// <summary>
        /// Initialize a new RegisterResourceException
        /// </summary>
        public RegisterResourceException()
        {
            // Default constructor
        }

        /// <summary>
        /// Initialize a new RegisterResourceException
        /// </summary>
        /// <param name="message">The error message</param>
        public RegisterResourceException(string message) : base(message)
        {
            // Default constructor
        }
    }
}
