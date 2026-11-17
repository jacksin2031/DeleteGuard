namespace DeleteGuard.Core.Services;

/// <summary>
/// Bounds and de-duplicates a stream of recent event keys.
/// The hard entry cap is intentional: event suppression must not itself become
/// an unbounded-memory denial-of-service surface.
/// </summary>
public sealed class RecentEventGate
{
    private readonly object _sync = new();
    private readonly Dictionary<string, DateTimeOffset> _recent;
    private readonly TimeSpan _duplicateWindow;
    private readonly TimeSpan _retentionWindow;
    private readonly int _maxEntries;

    public RecentEventGate(
        TimeSpan duplicateWindow,
        TimeSpan retentionWindow,
        int maxEntries,
        IEqualityComparer<string>? comparer = null)
    {
        if (duplicateWindow < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(duplicateWindow));
        }

        if (retentionWindow < duplicateWindow)
        {
            throw new ArgumentOutOfRangeException(nameof(retentionWindow), "Retention must be at least as long as the duplicate window.");
        }

        if (maxEntries <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxEntries));
        }

        _duplicateWindow = duplicateWindow;
        _retentionWindow = retentionWindow;
        _maxEntries = maxEntries;
        _recent = new Dictionary<string, DateTimeOffset>(comparer ?? StringComparer.Ordinal);
    }

    public int Count
    {
        get
        {
            lock (_sync)
            {
                return _recent.Count;
            }
        }
    }

    public bool TryAccept(string key, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        lock (_sync)
        {
            if (_recent.TryGetValue(key, out var previous) && now - previous < _duplicateWindow)
            {
                return false;
            }

            _recent[key] = now;
            Compact(now);
            return true;
        }
    }

    private void Compact(DateTimeOffset now)
    {
        if (_recent.Count <= _maxEntries)
        {
            return;
        }

        var staleKeys = _recent
            .Where(pair => now - pair.Value >= _retentionWindow)
            .Select(pair => pair.Key)
            .ToArray();

        foreach (var key in staleKeys)
        {
            _recent.Remove(key);
        }

        if (_recent.Count <= _maxEntries)
        {
            return;
        }

        var overflow = _recent.Count - _maxEntries;
        foreach (var key in _recent
                     .OrderBy(pair => pair.Value)
                     .Take(overflow)
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            _recent.Remove(key);
        }
    }
}
