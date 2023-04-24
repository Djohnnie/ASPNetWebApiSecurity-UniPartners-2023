using AspNetIdentity.Common.DataAccess;
using AspNetIdentity.Common.Entities;
using AspNetIdentity.Common.Handlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

namespace AspNetIdentity.Common.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static void ConfigureDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<AspNetIdentityDbContext>(options =>
        {
            options.UseSqlServer(configuration.GetValue<string>("ConnectionString"));
        });
    }
    public static void ConfigureMemoryDatabase(this IServiceCollection services)
    {
        services.AddDbContext<AspNetIdentityDbContext>(options =>
        {
            options.UseInMemoryDatabase("AspNetIdentity");
        });
    }

    public static void ConfigureBasicIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentityCore<Member>(options =>
        {
            options.Password = new PasswordOptions
            {
                RequiredLength = 4,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
                RequireNonAlphanumeric = false
            };
        });

        services.AddIdentity<Member, Role>()
            .AddEntityFrameworkStores<AspNetIdentityDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<PasswordValidator<Member>>();

        services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", options => { });

        services.AddAuthorization(options =>
        {
            options.AddPolicy("BasicAuthentication", new AuthorizationPolicyBuilder("BasicAuthentication").RequireAuthenticatedUser().Build());
        });
    }

    public static void ConfigureTokenIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentityCore<Member>(options =>
        {
            options.Password = new PasswordOptions
            {
                RequiredLength = 4,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
                RequireNonAlphanumeric = false
            };
        });

        services.AddIdentity<Member, Role>()
            .AddEntityFrameworkStores<AspNetIdentityDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<PasswordValidator<Member>>();

        services.AddAuthentication(o =>
        {
            o.DefaultAuthenticateScheme =

            o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = bool.Parse(configuration.GetValue<string>("JWT:RequireHttps"));
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = configuration.GetValue<string>("JWT:Issuer"),
                ValidAudience = configuration.GetValue<string>("JWT:Audience"),
                NameClaimType = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name,
                IssuerSigningKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("JWT:Secret")))
            };
        });

        services.AddAuthorization();
    }

    public static void ConfigureClaimsIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentityCore<Member>(options =>
        {
            options.Password = new PasswordOptions
            {
                RequiredLength = 4,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
                RequireNonAlphanumeric = false
            };
        });

        services.AddIdentity<Member, Role>()
            .AddEntityFrameworkStores<AspNetIdentityDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<PasswordValidator<Member>>();

        services.AddAuthentication(o =>
        {
            o.DefaultAuthenticateScheme =

            o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = bool.Parse(configuration.GetValue<string>("JWT:RequireHttps"));
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = configuration.GetValue<string>("JWT:Issuer"),
                ValidAudience = configuration.GetValue<string>("JWT:Audience"),
                NameClaimType = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name,
                IssuerSigningKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("JWT:Secret")))
            };
        });

        services.AddAuthorization(options =>
        {
            options.AddPolicy("AdminPolicy", policy => policy.RequireClaim("Admin"));
            options.AddPolicy("SuperAdminPolicy", policy => policy.RequireClaim("SuperAdmin"));
        });
    }

    public static void ConfigureEncryptedIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentityCore<Member>(options =>
        {
            options.Password = new PasswordOptions
            {
                RequiredLength = 4,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
                RequireNonAlphanumeric = false
            };
        });

        services.AddIdentity<Member, Role>()
            .AddEntityFrameworkStores<AspNetIdentityDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<PasswordValidator<Member>>();

        services.AddAuthentication(o =>
        {
            o.DefaultAuthenticateScheme =

            o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = bool.Parse(configuration.GetValue<string>("JWT:RequireHttps"));
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidIssuer = configuration.GetValue<string>("JWT:Issuer"),
                ValidAudience = configuration.GetValue<string>("JWT:Audience"),
                NameClaimType = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Name,
                IssuerSigningKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("JWT:Secret"))),
                TokenDecryptionKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("JWT:Secret")))
            };
        });

        services.AddAuthorization(options =>
        {
            options.AddPolicy("AdminPolicy", policy => policy.RequireClaim("Admin"));
            options.AddPolicy("SuperAdminPolicy", policy => policy.RequireClaim("SuperAdmin"));
        });
    }

    public static void ConfigureSwaggerWithBasicIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddEndpointsApiExplorer();

        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Basic_Auth_API",
                Version = "v1"
            });
            c.AddSecurityDefinition("basic", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "basic",
                In = ParameterLocation.Header,
                Description = "Basic Authorization header using the Basic scheme."
            });
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "basic"
                            }
                        },
                        new string[] {}
                    }
                });
        });
    }

    public static void ConfigureSwaggerWithTokenIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddEndpointsApiExplorer();

        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "JWTToken_Auth_API",
                Version = "v1"
            });
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 1safsfsdfdfd\"",
            });
            c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
            });
        });
    }
}