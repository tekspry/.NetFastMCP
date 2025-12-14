using Microsoft.AspNetCore.Authorization; 

namespace FastMCP.Hosting;

// Custom Authorization Handler for PolicyNameRequirement
// This is a simplified handler. In a real app, each named policy (e.g., "AdminOnly")
// would have a specific handler that checks roles, claims, or other conditions.
public class PolicyNameRequirementHandler : AuthorizationHandler<PolicyNameRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PolicyNameRequirement requirement)
    {
        // For demonstration purposes, if the user is authenticated, we'll generally succeed.
        // Replace this with actual policy logic based on `requirement.PolicyName`.
        if (context.User.Identity?.IsAuthenticated == true)
        {
            // Example: if requirement.PolicyName was "AdminOnly", you would check context.User.IsInRole("Admin")
            // For now, any authenticated user satisfies a generic policy.
            context.Succeed(requirement);
        }
        else
        {
            // Fail if not authenticated or specific policy not met
            context.Fail();
        }
        return Task.CompletedTask;
    }
}