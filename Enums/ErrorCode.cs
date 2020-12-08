namespace AntiProxy.Enums
{
    public enum ErrorCode
    {
        NoError = 0,
        NoInput = -1,
        InvalidAddress = -2,
        PrivateAddress = -3,
        CantReachDB = -4,
        IPBanned = -5,
        InvalidContact = -6
    }
}
