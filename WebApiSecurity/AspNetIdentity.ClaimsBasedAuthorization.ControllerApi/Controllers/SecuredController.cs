using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspNetIdentity.ClaimsBasedAuthorization.ControllerApi.Controllers;

[ApiController]
[Authorize]
[Route("/")]
public class SecuredController : ControllerBase
{
    private readonly IApiHelper<SecuredManager> _helper;

    public SecuredController(IApiHelper<SecuredManager> helper)
    {
        _helper = helper;
    }

    [HttpGet("/secured", Name = "GetSecured")]
    public Task<IResult> GetSecured()
    {
        return _helper.Execute(x => x.GetSecured());
    }

    [HttpGet("/admin", Name = "GetAdmin")]
    [Authorize("AdminPolicy")]
    public Task<IResult> GetAdmin()
    {
        return _helper.Execute(x => x.GetAdmin());
    }

    [HttpGet("/superadmin", Name = "GetSuperAdmin")]
    [Authorize("SuperAdminPolicy")]
    public Task<IResult> GetSuperAdmin()
    {
        return _helper.Execute(x => x.GetSuperAdmin());
    }
}