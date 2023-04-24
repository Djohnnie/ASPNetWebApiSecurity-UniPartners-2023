using AspNetIdentity.Common.DataAccess;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetIdentity.Common.Middleware;

public static class DatabaseMigrationMiddlewareExtensions
{
    public static IApplicationBuilder UseDatabaseMigration(this IApplicationBuilder builder, bool inMemory)
    {
        return builder.UseMiddleware<DatabaseMigrationMiddleware>(inMemory);
    }
}

public class DatabaseMigrationMiddleware
{
    private static bool _isMigrated;

    private readonly RequestDelegate _next;
    private readonly IServiceProvider _serviceProvider;
    private readonly bool _inMemory;

    public DatabaseMigrationMiddleware(RequestDelegate next, IServiceProvider serviceProvider, bool inMemory)
    {
        _next = next;
        _serviceProvider = serviceProvider;
        _inMemory = inMemory;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!_inMemory && !_isMigrated)
        {
            using (var serviceScope = _serviceProvider.CreateScope())
            {
                var dbContext = serviceScope.ServiceProvider.GetService<AspNetIdentityDbContext>();
                await dbContext.Database.MigrateAsync();
            }

            _isMigrated = true;
        }

        await _next(context);
    }
}