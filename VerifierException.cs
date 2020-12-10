using AntiProxy.Enums;
using System;

namespace AntiProxy
{
    /// <summary>
    /// Thrown when the proxy verifier encounters an error that requires human intervention.
    /// </summary>
    public class VerifierException : Exception
    {
        private ErrorCode _error;

        public VerifierException(ErrorCode error) : base()
        {
            _error = error;
        }

        public override string ToString()
        {
            return "AntiProxy Verifier encountered an error response. Error code: " + _error;
        }
    }
}
