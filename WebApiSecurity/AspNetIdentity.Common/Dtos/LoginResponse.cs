﻿namespace AspNetIdentity.Common.Dtos;

public class LoginResponse
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}