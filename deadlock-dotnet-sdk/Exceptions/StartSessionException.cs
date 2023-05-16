﻿namespace deadlock_dotnet_sdk.Exceptions
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

        public StartSessionException(string? message) : base(message)
        {
        }

        public StartSessionException(string? message, Exception? innerException) : base(message, innerException)
        {
        }
    }
}
