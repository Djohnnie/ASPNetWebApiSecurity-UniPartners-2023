namespace AspNetIdentity.Common.Managers;

public class StatusManager
{
    public Task<string> GetStatus()
    {
        return Task.FromResult("Hello ASP.NET Identity!");
    }
}