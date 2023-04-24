namespace AspNetIdentity.Common.Dtos;

public class RefreshResponse
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}