using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AspNetIdentity.TokenAuthentication.ControllerApi.Controllers;

[ApiController]
[Authorize]
[Route("/secured")]
public class SecuredController : ControllerBase
{
    private readonly IApiHelper<SecuredManager> _helper;

    public SecuredController(IApiHelper<SecuredManager> helper)
    {
        _helper = helper;
    }

    [HttpGet(Name = "GetSecured")]
    public Task<IResult> GetSecured()
    {
        return _helper.Execute(x => x.GetSecured());
    }
}