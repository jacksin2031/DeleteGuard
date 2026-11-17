namespace DeleteGuard.Broker;

/// <summary>Raised when an operation needs the minifilter driver and it cannot be reached.</summary>
internal sealed class DriverUnavailableException : Exception
{
    public DriverUnavailableException(string message) : base(message)
    {
    }
}
