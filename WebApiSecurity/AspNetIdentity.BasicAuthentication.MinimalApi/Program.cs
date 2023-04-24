using AspNetIdentity.Common.DependencyInjection;
using AspNetIdentity.Common.Dtos;
using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using AspNetIdentity.Common.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddScoped(typeof(IApiHelper<>), typeof(ApiHelper<>));
builder.Services.AddScoped<StatusManager>();
builder.Services.AddScoped<SecuredManager>();
builder.Services.AddScoped<IdentityManager>();

builder.Services.ConfigureMemoryDatabase();
builder.Services.ConfigureBasicIdentity(builder.Configuration);
builder.Services.ConfigureSwaggerWithBasicIdentity(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseDatabaseMigration(inMemory: true);


app.MapGet("/", (IApiHelper<StatusManager> helper) =>
{
    return helper.Execute(x => x.GetStatus());
}).WithName("GetStatus").WithOpenApi().AllowAnonymous();


app.MapPost("/register", (IApiHelper<IdentityManager> helper, RegisterRequest request) =>
{
    return helper.Post(x => x.Register(request));
}).WithName("Register").WithOpenApi().AllowAnonymous();


app.MapGet("/secured", (IApiHelper<SecuredManager> helper) =>
{
    return helper.Execute(x => x.GetSecured());
}).WithName("GetSecured").WithOpenApi().RequireAuthorization("BasicAuthentication");


app.Run();