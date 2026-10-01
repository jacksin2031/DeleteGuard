namespace DeleteGuard.Core.Services;

/// <summary>
/// Limits unsolicited approval prompts so an untrusted process cannot create
/// an unbounded stream of modal dialogs/UAC opportunities by repeatedly
/// attempting protected deletes.
/// </summary>
public sealed class ApprovalPromptLimiter
{
    private readonly object _sync = new();
    private readonly Queue<DateTimeOffset> _accepted = new();
    private readonly int _maxPrompts;
    private readonly TimeSpan _window;

    public ApprovalPromptLimiter(int maxPrompts, TimeSpan window)
    {
        if (maxPrompts <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPrompts));
        }

        if (window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(window));
        }

        _maxPrompts = maxPrompts;
        _window = window;
    }

    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _accepted.Count;
            }
        }
    }

    public bool TryAcquire(DateTimeOffset now)
    {
        lock (_sync)
        {
            while (_accepted.Count > 0 && now - _accepted.Peek() >= _window)
            {
                _accepted.Dequeue();
            }

            if (_accepted.Count >= _maxPrompts)
            {
                return false;
            }

            _accepted.Enqueue(now);
            return true;
        }
    }
}
