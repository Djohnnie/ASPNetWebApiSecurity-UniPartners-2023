using AspNetIdentity.Common.Dtos;
using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspNetIdentity.RefreshTokens.ControllerApi.Controllers;

[ApiController]
[Route("/")]
public class AuthenticationController : ControllerBase
{
    private readonly IApiHelper<IdentityManager> _helper;

    public AuthenticationController(IApiHelper<IdentityManager> helper)
    {
        _helper = helper;
    }

    [HttpPost("/register", Name = "Register")]
    public Task<IResult> Register(RegisterRequest request)
    {
        return _helper.Post(x => x.Register(request));
    }

    [HttpPost("/login", Name = "Login")]
    public Task<IResult> Login(LoginRequest request)
    {
        return _helper.Post(x => x.LoginWithRefresh(request));
    }

    [HttpPost("/refresh", Name = "Refresh")]
    public Task<IResult> Refresh(RefreshRequest request)
    {
        return _helper.Post(x => x.RefreshToken(request));
    }

    [Authorize]
    [HttpPost("/revoke", Name = "Revoke")]
    public Task<IResult> Revoke()
    {
        return _helper.Execute(x => x.RevokeRefreshToken());
    }
}