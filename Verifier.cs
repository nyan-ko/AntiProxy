using AntiProxy.Enums;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using TShockAPI;

namespace AntiProxy
{
    public class Verifier
    {
        private const float HIGH_RISK_THRESHOLD = 0.99F;
        private const float CAUTION_THRESHOLD = 0.95F;

        private static HttpClient _client = new HttpClient();

        private VerifierInputFlags _flags;
        private string _email;

        public Verifier(string email) : this(email, VerifierInputFlags.None) { }

        public Verifier(string email, VerifierInputFlags flags)
        {
            _email = email;
            _flags = flags;
            _client.Timeout = TimeSpan.FromMilliseconds(3000);
        }

        public async Task<RiskType> GetProxyRiskAsync(string ip)
        {
            // thanks cy for the code!!
            string query = "https://check.getipintel.net/check.php?" +
                $"ip={ip}" +
                $"&contact={_email}";

            if (_flags != VerifierInputFlags.None)
            {
                query += $"&flags={_flags}";
            }

            HttpResponseMessage result;
            try
            {
                result = await _client.GetAsync(query);
            }
            catch (TaskCanceledException)
            {
                TShock.Log.ConsoleError($"Request timed out for ip {ip}");
                TShock.Log.Write($"Request timed out for ip {ip}", TraceLevel.Error);
                return RiskType.Unknown;
            }

            //if (!result.IsSuccessStatusCode)
            //{
            //    throw new Exception("Proxy checker request failed.");
            //}
            //else
            //{ 
                string response = await result.Content.ReadAsStringAsync();
                ErrorCode error = GetErrorCode(response);

                if (error < ErrorCode.NoError)
                {
                    throw new VerifierException(error);
                }

                double prob = double.Parse(response);

                if (prob >= HIGH_RISK_THRESHOLD)
                {
                    return RiskType.High;
                }
                else if (prob >= CAUTION_THRESHOLD)
                {
                    return RiskType.Caution;
                }
                else if (prob < CAUTION_THRESHOLD && prob >= 0)
                {
                    return RiskType.Low;
                }
                else
                {
                    return RiskType.Unknown;
                }
            //}
        }

        // see if the response is an error code first before treating it as a probability
        private ErrorCode GetErrorCode(string response)
        {
            switch (response)
            {
                case "-1":
                    return ErrorCode.NoInput;
                case "-2":
                    return ErrorCode.InvalidAddress;  // -1 and -2 shouldn't ever happen but :shrug:
                case "-3":
                    return ErrorCode.PrivateAddress;  // not too sure about this
                case "-4":
                    return ErrorCode.CantReachDB;  // requires someone to watch http://www.twitter.com/blackdotsh until db is updated
                case "-5":
                    return ErrorCode.IPBanned;
                case "-6":
                    return ErrorCode.InvalidContact;  // -5 and -6 both result in an alert so someone can email contact@getipintel.net about the problem
                default:
                    return ErrorCode.NoError;
            }
        }
    }
}
