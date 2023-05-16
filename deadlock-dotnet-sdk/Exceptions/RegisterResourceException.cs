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

        public RegisterResourceException(string? message) : base(message)
        { }

        public RegisterResourceException(string? message, Exception innerException) : base(message, innerException)
        { }
    }
}
