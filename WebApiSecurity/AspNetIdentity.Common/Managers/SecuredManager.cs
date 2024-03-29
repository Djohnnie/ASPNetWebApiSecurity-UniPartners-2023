﻿using Microsoft.AspNetCore.Http;

namespace AspNetIdentity.Common.Managers;

public class SecuredManager
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public SecuredManager(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Task<string> GetSecured()
    {
        return Task.FromResult($"Hello Secured {GetUserName()}");
    }

    public Task<string> GetAdmin()
    {
        return Task.FromResult($"Hello Admin {GetUserName()}");
    }

    public Task<string> GetSuperAdmin()
    {
        return Task.FromResult($"Hello Super Admin {GetUserName()}");
    }

    private string GetUserName()
    {
        return _httpContextAccessor.HttpContext?.User.Identity.Name ??
            _httpContextAccessor.HttpContext?.User.Claims.SingleOrDefault(x=>x.Type == "name")?.Value ?? "Unknown";
    }
}