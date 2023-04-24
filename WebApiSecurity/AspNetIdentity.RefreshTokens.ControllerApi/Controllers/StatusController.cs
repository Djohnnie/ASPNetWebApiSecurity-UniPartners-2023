using AspNetIdentity.Common.Helpers;
using AspNetIdentity.Common.Managers;
using Microsoft.AspNetCore.Mvc;

namespace AspNetIdentity.RefreshTokens.ControllerApi.Controllers;

[ApiController]
[Route("/")]
public class StatusController : ControllerBase
{
    private readonly IApiHelper<StatusManager> _helper;

    public StatusController(IApiHelper<StatusManager> helper)
    {
        _helper = helper;
    }

    [HttpGet(Name = "GetStatus")]
    public Task<IResult> Get()
    {
        return _helper.Execute(x => x.GetStatus());
    }
}