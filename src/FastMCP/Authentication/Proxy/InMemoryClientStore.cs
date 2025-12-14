using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace FastMCP.Authentication.Proxy;

/// <summary>
/// In-memory implementation of IClientStore.
/// For production, consider using a persistent store (database, Redis, etc.).
/// </summary>
public class InMemoryClientStore : IClientStore
{
    private readonly ConcurrentDictionary<string, OAuthClientRegistration> _clients = new();

    public Task StoreClientAsync(string clientId, OAuthClientRegistration client)
    {
        _clients[clientId] = client;
        return Task.CompletedTask;
    }

    public Task<OAuthClientRegistration?> GetClientAsync(string clientId)
    {
        _clients.TryGetValue(clientId, out var client);
        return Task.FromResult<OAuthClientRegistration?>(client);
    }

    public Task RemoveClientAsync(string clientId)
    {
        _clients.TryRemove(clientId, out _);
        return Task.CompletedTask;
    }
}