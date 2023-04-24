namespace AspNetIdentity.Common.Dtos;

public class RefreshRequest
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}