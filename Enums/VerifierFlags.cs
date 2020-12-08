namespace AntiProxy.Enums
{
    /// <summary>
    /// Input flags able to specify speed and thoroughness of verifier. Flag documentation: https://getipintel.net/
    /// </summary>
    public enum VerifierInputFlags
    {
        m,  // Fastest, least false positives, lets some IPs through, only cares about proxies and vpns
        b,
        None,
        f  // Slowest, performs full ip check, can take upwards of 5 seconds
    }
}
