using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddScoped(typeof(IApiHelper<>), typeof(ApiHelper<>));
builder.Services.AddTransient<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddScoped<StatusManager>();
builder.Services.AddScoped<SecuredManager>();

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
        Flows = new OpenApiOAuthFlows
        {
            // https://www.linkedin.com/advice/0/what-trade-offs-between-implicit-grant-flow-authorization
            Implicit = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri($"https://dev-djohnnie.eu.auth0.com/authorize?audience=my-api"),
                Scopes = new Dictionary<string, string>
                  {
                      { "openid", "OpenId" },
                      { "profile", "Profile" },
                      { "email", "email" }
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
              new[] { "openid", "profile", "email" }
          }
      });
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

}).AddJwtBearer(options =>
{
    options.Authority = $"https://dev-djohnnie.eu.auth0.com/";
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = false,
        ValidIssuer = "https://dev-djohnnie.eu.auth0.com/",
        ValidAudience = "my-api",
        NameClaimType = "user-nickname"
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();


if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(settings =>
    {
        settings.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1.0");
        settings.OAuthClientId("onLgyE1xNYHGGQjH5P5AbLEmqUOb4RMh");
    });
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();


app.MapGet("/", (IApiHelper<StatusManager> helper) =>
{
    return helper.Execute(x => x.GetStatus());
}).WithName("GetStatus").WithOpenApi().AllowAnonymous();


app.MapGet("/secured", (IApiHelper<SecuredManager> helper) =>
{
    return helper.Execute(x => x.GetSecured());
}).WithName("GetSecured").WithOpenApi().RequireAuthorization();


app.Run();