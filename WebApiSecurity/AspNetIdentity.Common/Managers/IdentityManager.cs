using AspNetIdentity.Common.Dtos;
using AspNetIdentity.Common.Entities;
using AspNetIdentity.Common.Exceptions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AspNetIdentity.Common.Managers;

public class IdentityManager
{
    private readonly UserManager<Member> _userManager;
    private readonly RoleManager<Role> _roleManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IConfiguration _configuration;

    public IdentityManager(
        UserManager<Member> userManager,
        RoleManager<Role> roleManager,
        IHttpContextAccessor httpContextAccessor,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _httpContextAccessor = httpContextAccessor;
        _configuration = configuration;
    }

    public async Task<Member> Authenticate(string username, string password)
    {
        var member = await _userManager.FindByNameAsync(username);

        if (member == null)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var authenticated = await _userManager.CheckPasswordAsync(member, password);

        if (!authenticated)
        {
            throw new IdentityException("Invalid username or password!");
        }

        return member;
    }

    public async Task<LoginResponse> LoginWithToken(LoginRequest request)
    {
        var member = await _userManager.FindByNameAsync(request.UserName);

        if (member == null)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var authenticated = await _userManager.CheckPasswordAsync(member, request.Password);

        if (!authenticated)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var issuer = _configuration.GetValue<string>("JWT:Issuer");
        var audience = _configuration.GetValue<string>("JWT:Audience");

        var claims = new List<Claim>
        {
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sid, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name, $"{member.UserName}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, $"{Guid.NewGuid()}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Iss, issuer),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Aud, audience)
        };

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var handler = new JwtSecurityTokenHandler();

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.Now.AddHours(4),
            Claims = claims.ToDictionary(k => k.Type, e => (object)e.Value),
            SigningCredentials = new SigningCredentials(
                authSigningKey, SecurityAlgorithms.HmacSha512)
        });

        return new LoginResponse
        {
            Token = handler.WriteToken(token)
        };
    }

    public async Task<LoginResponse> LoginWithClaims(LoginRequest request)
    {
        var member = await _userManager.FindByNameAsync(request.UserName);

        if (member == null)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var authenticated = await _userManager.CheckPasswordAsync(member, request.Password);

        if (!authenticated)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var issuer = _configuration.GetValue<string>("JWT:Issuer");
        var audience = _configuration.GetValue<string>("JWT:Audience");

        var claims = new List<Claim>
        {
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sid, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name, $"{member.UserName}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, $"{Guid.NewGuid()}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Iss, issuer),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Aud, audience)
        };

        foreach (var name in await _userManager.GetRolesAsync(member))
        {
            var role = _roleManager.Roles.SingleOrDefault(x => x.Name == name);
            var claim = await _roleManager.GetClaimsAsync(role);
            claims.AddRange(claim);
        }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var handler = new JwtSecurityTokenHandler();

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.Now.AddHours(4),
            Claims = claims.ToDictionary(k => k.Type, e => (object)e.Value),
            SigningCredentials = new SigningCredentials(
                authSigningKey, SecurityAlgorithms.HmacSha512)
        });

        return new LoginResponse
        {
            Token = handler.WriteToken(token)
        };
    }

    public async Task<LoginResponse> LoginWithEncryptedToken(LoginRequest request)
    {
        var member = await _userManager.FindByNameAsync(request.UserName);

        if (member == null)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var authenticated = await _userManager.CheckPasswordAsync(member, request.Password);

        if (!authenticated)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var issuer = _configuration.GetValue<string>("JWT:Issuer");
        var audience = _configuration.GetValue<string>("JWT:Audience");

        var claims = new List<Claim>
        {
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sid, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name, $"{member.UserName}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, $"{Guid.NewGuid()}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Iss, issuer),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Aud, audience)
        };

        foreach (var name in await _userManager.GetRolesAsync(member))
        {
            var role = _roleManager.Roles.SingleOrDefault(x => x.Name == name);
            var claim = await _roleManager.GetClaimsAsync(role);
            claims.AddRange(claim);
        }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var handler = new JwtSecurityTokenHandler();

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.Now.AddHours(4),
            Claims = claims.ToDictionary(k => k.Type, e => (object)e.Value),
            SigningCredentials = new SigningCredentials(
                authSigningKey, SecurityAlgorithms.HmacSha512),
            EncryptingCredentials = new EncryptingCredentials(
                authSigningKey, JwtConstants.DirectKeyUseAlg, SecurityAlgorithms.Aes256CbcHmacSha512)
        });

        return new LoginResponse
        {
            Token = handler.WriteToken(token)
        };
    }

    public async Task<LoginResponse> LoginWithRefresh(LoginRequest request)
    {
        var member = await _userManager.FindByNameAsync(request.UserName);

        if (member == null)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var authenticated = await _userManager.CheckPasswordAsync(member, request.Password);

        if (!authenticated)
        {
            throw new IdentityException("Invalid username or password!");
        }

        var issuer = _configuration.GetValue<string>("JWT:Issuer");
        var audience = _configuration.GetValue<string>("JWT:Audience");

        var claims = new List<Claim>
        {
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sid, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name, $"{member.UserName}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, $"{Guid.NewGuid()}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Iss, issuer),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Aud, audience)
        };

        foreach (var name in await _userManager.GetRolesAsync(member))
        {
            var role = _roleManager.Roles.SingleOrDefault(x => x.Name == name);
            var claim = await _roleManager.GetClaimsAsync(role);
            claims.AddRange(claim);
        }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var handler = new JwtSecurityTokenHandler();

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.Now.AddHours(4),
            Claims = claims.ToDictionary(k => k.Type, e => (object)e.Value),
            SigningCredentials = new SigningCredentials(
                authSigningKey, SecurityAlgorithms.HmacSha512)
        });

        var refreshBytes = new byte[32];
        Random.Shared.NextBytes(refreshBytes);
        var refreshToken = Convert.ToBase64String(refreshBytes);

        member.RefreshToken = refreshToken;
        member.RefreshTokenExpiry = DateTime.UtcNow.AddDays(1);

        await _userManager.UpdateAsync(member);

        return new LoginResponse
        {
            Token = handler.WriteToken(token),
            RefreshToken = refreshToken
        };
    }

    public async Task<RefreshResponse> RefreshToken(RefreshRequest request)
    {
        var principal = GetPrincipalFromExpiredToken(request.Token);

        var member = await _userManager.FindByNameAsync(principal.Identity.Name);

        if (member == null || member.RefreshToken != request.RefreshToken || member.RefreshTokenExpiry < DateTime.UtcNow)
        {
            throw new IdentityException("Invalid token!");
        }

        var issuer = _configuration.GetValue<string>("JWT:Issuer");
        var audience = _configuration.GetValue<string>("JWT:Audience");

        var claims = new List<Claim>
        {
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sid, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name, $"{member.UserName}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, $"{Guid.NewGuid()}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, $"{member.Id}"),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Iss, issuer),
            new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Aud, audience)
        };

        foreach (var name in await _userManager.GetRolesAsync(member))
        {
            var role = _roleManager.Roles.SingleOrDefault(x => x.Name == name);
            var claim = await _roleManager.GetClaimsAsync(role);
            claims.AddRange(claim);
        }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var handler = new JwtSecurityTokenHandler();

        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.Now.AddHours(4),
            Claims = claims.ToDictionary(k => k.Type, e => (object)e.Value),
            SigningCredentials = new SigningCredentials(
                authSigningKey, SecurityAlgorithms.HmacSha512)
        });

        var refreshBytes = new byte[32];
        Random.Shared.NextBytes(refreshBytes);
        var refreshToken = Convert.ToBase64String(refreshBytes);

        member.RefreshToken = refreshToken;
        member.RefreshTokenExpiry = DateTime.UtcNow.AddDays(1);

        await _userManager.UpdateAsync(member);

        return new RefreshResponse
        {
            Token = handler.WriteToken(token),
            RefreshToken = refreshToken
        };
    }

    public async Task RevokeRefreshToken()
    {
        var member = await _userManager.FindByNameAsync(_httpContextAccessor.HttpContext.User.Identity.Name);

        if (member == null)
        {
            throw new IdentityException("Invalid!");
        }

        member.RefreshToken = null;
        member.RefreshTokenExpiry = null;

        await _userManager.UpdateAsync(member);
    }

    public async Task<RegisterResponse> Register(RegisterRequest request)
    {
        var member = new Member
        {
            SecurityStamp = $"{Guid.NewGuid()}",
            UserName = request.UserName
        };

        var result = await _userManager.CreateAsync(member, request.Password);

        if (!result.Succeeded)
        {
            throw new IdentityException("Registering user failed!");
        }

        if (request.Claims != null)
        {
            foreach (var claim in request.Claims)
            {
                var role = new Role { Name = claim };
                await _roleManager.CreateAsync(role);
                await _roleManager.AddClaimAsync(role, new Claim(claim, claim));
                await _userManager.AddToRoleAsync(member, claim);
            }
        }

        return new RegisterResponse { };
    }

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = authSigningKey,
            ValidateLifetime = false, //here we are saying that we don't care about the token's expiration date
            NameClaimType = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken securityToken;
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
        var jwtSecurityToken = securityToken as JwtSecurityToken;
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");
        return principal;
    }
}