using System.Threading.Tasks;

namespace FastMCP.Authentication.Proxy;

/// <summary>
/// Interface for storing and retrieving OAuth client registrations.
/// </summary>
public interface IClientStore
{
    /// <summary>
    /// Stores a client registration.
    /// </summary>
    Task StoreClientAsync(string clientId, OAuthClientRegistration client);

    /// <summary>
    /// Retrieves a client registration by client ID.
    /// </summary>
    Task<OAuthClientRegistration?> GetClientAsync(string clientId);

    /// <summary>
    /// Removes a client registration.
    /// </summary>
    Task RemoveClientAsync(string clientId);
}