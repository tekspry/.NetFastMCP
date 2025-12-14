using Microsoft.AspNetCore.Authorization; 

namespace FastMCP.Hosting;

public class PolicyNameRequirement : IAuthorizationRequirement
{
    public string PolicyName { get; }

    public PolicyNameRequirement(string policyName)
    {
        PolicyName = policyName;
    }
}