using AspNetIdentity.Common.DependencyInjection;
using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using AspNetIdentity.Common.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddScoped(typeof(IApiHelper<>), typeof(ApiHelper<>));
builder.Services.AddScoped<StatusManager>();
builder.Services.AddScoped<SecuredManager>();
builder.Services.AddScoped<IdentityManager>();

builder.Services.ConfigureMemoryDatabase();
builder.Services.ConfigureTokenIdentity(builder.Configuration);
builder.Services.ConfigureSwaggerWithTokenIdentity(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.UseDatabaseMigration(inMemory: true);

app.Run();