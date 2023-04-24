namespace AspNetIdentity.Common.Dtos;

public class RegisterRequest
{
    public string UserName { get; set; }
    public string Password { get; set; }
    public List<string> Claims { get; set; }
}