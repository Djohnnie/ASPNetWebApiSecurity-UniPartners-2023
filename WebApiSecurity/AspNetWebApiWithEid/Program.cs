using AspNetIdentity.Common.DependencyInjection;
using AspNetIdentity.Common.DataAccess;
using AspNetIdentity.Common.Entities;
using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using AspNetWebApiWithEid.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddScoped(typeof(IApiHelper<>), typeof(ApiHelper<>));
builder.Services.AddScoped<StatusManager>();
builder.Services.AddScoped<SecuredManager>();
builder.Services.AddScoped<IdentityManager>();

builder.Services.ConfigureMemoryDatabase();
builder.Services.AddIdentity<Member, Role>()
            .AddEntityFrameworkStores<AspNetIdentityDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<PasswordValidator<Member>>();

builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "API Documentation",
        Version = "v1.0",
        Description = ""
    });
    options.ResolveConflictingActions(x => x.First());
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        BearerFormat = "JWT",
        OpenIdConnectUrl = new Uri($"https://www.e-contract.be/eid-idp/oidc/ident/.well-known/openid-configuration"),
        Flows = new OpenApiOAuthFlows
        {
            // https://www.linkedin.com/advice/0/what-trade-offs-between-implicit-grant-flow-authorization
            AuthorizationCode = new OpenApiOAuthFlow
            {
                TokenUrl = new Uri($"https://www.e-contract.be/eid-idp/oidc/ident/token"),
                AuthorizationUrl = new Uri($"https://www.e-contract.be/eid-idp/oidc/ident/authorize"),
                Scopes = new Dictionary<string, string>
                  {
                      { "openid", "OpenId" }
                  }
            }
        }
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
      {
          {
              new OpenApiSecurityScheme
              {
                  Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "oauth2" }
              },
              new[] { "openid" }
          }
      });
});

builder.Services.AddCors();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(settings =>
    {
        settings.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1.0");
        settings.OAuthClientId("c1a5154e-e156-4569-b0a1-bda0088c4ced");
        settings.OAuthClientSecret("29b7075e-8e4d-4fde-89b2-e1fe2af6e966");
        settings.OAuthUseBasicAuthenticationWithAccessCodeGrant();
        settings.OAuthUsePkce();
    });
}

app.UseHttpsRedirection();
app.UseEidAuthorization();

app.UseCors(c => { c.AllowAnyOrigin(); });

app.MapGet("/", (IApiHelper<StatusManager> helper) =>
{
    return helper.Execute(x => x.GetStatus());
}).WithName("GetStatus").WithOpenApi().AllowAnonymous();


app.MapGet("/secured", (IApiHelper<SecuredManager> helper) =>
{
    return helper.Execute(x => x.GetSecured());
}).WithName("GetSecured").WithOpenApi().RequireAuthorization();

app.Run();