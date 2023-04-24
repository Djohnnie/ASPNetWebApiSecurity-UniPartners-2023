using AspNetIdentity.Common.Dtos;
using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Mvc;

namespace AspNetIdentity.BasicAuthentication.ControllerApi.Controllers;

[ApiController]
[Route("/")]
public class AuthenticationController
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
}