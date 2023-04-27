using System.Security.Claims;

namespace AspNetWebApiWithEid.Middleware;

public static class EidAuthorizationMiddlewareExtensions
{
    public static void UseEidAuthorization(this IApplicationBuilder builder)
    {
        builder.UseMiddleware<EidAuthorizationMiddleware>();
    }
}

public class EidAuthorizationMiddleware
{
    private readonly RequestDelegate _next;

    public EidAuthorizationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

        using var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

        var info = await httpClient.GetFromJsonAsync<UserInfo>(
            "https://www.e-contract.be/eid-idp/oidc/ident/userinfo");

        if (context.User != null)
        {
            var claims = new List<Claim>
                {
                    new Claim("Sub", info.Sub),
                    new Claim("Birthdate", info.Birthdate),
                    new Claim("Gender", info.Gender),
                    new Claim("Name", info.Name),
                };

            context.User.Identities.Single().AddClaims(claims);

            //var appIdentity = new ClaimsIdentity(claims);
            //context.User.AddIdentity(appIdentity);
        }

        await _next(context);
    }

    private class UserInfo
    {
        public string Sub { get; set; }
        public string Birthdate { get; set; }
        public string Gender { get; set; }
        public string Name { get; set; }
    }
}