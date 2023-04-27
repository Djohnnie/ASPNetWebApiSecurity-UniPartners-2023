using AspNetIdentity.Common.DependencyInjection;
using AspNetIdentity.Common.DataAccess;
using AspNetIdentity.Common.Entities;
using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Identity.Web;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddScoped(typeof(IApiHelper<>), typeof(ApiHelper<>));
builder.Services.AddScoped<StatusManager>();
builder.Services.AddScoped<SecuredManager>();
builder.Services.AddScoped<IdentityManager>();

builder.Services.AddEndpointsApiExplorer();

builder.Services.ConfigureMemoryDatabase();
builder.Services.AddIdentity<Member, Role>()
            .AddEntityFrameworkStores<AspNetIdentityDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<PasswordValidator<Member>>();

builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityRequirement(new OpenApiSecurityRequirement() {
    {
        new OpenApiSecurityScheme {
            Reference = new OpenApiReference {
                Type = ReferenceType.SecurityScheme,
                Id = "oauth2"
            },
            Scheme = "oauth2",
            Name = "oauth2",
            In = ParameterLocation.Header
        },
        new List <string> ()
    }});
    c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            Implicit = new OpenApiOAuthFlow()
            {
                AuthorizationUrl = new Uri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
                TokenUrl = new Uri("https://login.microsoftonline.com/common/common/v2.0/token"),
                Scopes = new Dictionary<string, string>() { { "api://0bd96818-2b39-46e4-8a4f-cae9e503b853/access_as_user", "" } }
            }
        }
    });
});


builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));
builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.OAuthAppName("Swagger Client");
        options.OAuthClientId("0bd96818-2b39-46e4-8a4f-cae9e503b853");
        options.OAuthClientSecret("0Am8Q~yGUbhgE5NvmDcY.eBPzQ3kbP_jkvQdTbuI");
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