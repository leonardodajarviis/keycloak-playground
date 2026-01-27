using System.Security.Claims;
using Keycloak.Net.Abstractions;
using Keycloak.Net.Models;
using Keycloak.Net.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace Keycloak.Net.Extensions;

/// <summary>
/// Extension methods for registering Keycloak services and authentication in an IServiceCollection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers a Keycloak user provider that maps claims from the HttpContext to a Keycloak user context.
    /// </summary>
    public const string KeycloakScheme = "Keycloak";

    /// <summary>
    /// Registers the ClaimsUserProvider as the implementation for IKeycloakUserProvider.
    /// </summary>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TUserKey"></typeparam>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddKeycloakUserProvider<TUser, TUserKey>(this IServiceCollection services)
        where TUser : KeycloakUserContext<TUserKey>, new()
    {
        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        services.AddScoped<IKeycloakUserProvider<TUser, TUserKey>, ClaimsUserProvider<TUser, TUserKey>>();

        return services;
    }

    /// <summary>
    /// Registers Keycloak authentication services including JWT Bearer authentication.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public static IServiceCollection AddKeycloakAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var keycloakOptions = configuration.GetSection("Keycloak").Get<KeycloakOptions>()
            ?? throw new InvalidOperationException("Keycloak configuration section is missing.");

        services.Configure<KeycloakOptions>(configuration.GetSection("Keycloak"));

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(opt =>
            {
                opt.Authority = keycloakOptions.Authority;
                opt.Audience = keycloakOptions.Audience;
                opt.RequireHttpsMetadata = keycloakOptions.RequireHttpsMetadata;

                // Use custom TokenValidationParameters if provided, otherwise build from options
                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = keycloakOptions.Authority,

                    ValidateAudience = true,
                    // Lấy danh sách Audience từ config, nếu không có thì dùng Audience chính
                    ValidAudiences = keycloakOptions.ValidAudiences ?? [keycloakOptions.Audience],

                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1),

                    NameClaimType = "preferred_username",
                    RoleClaimType = ClaimTypes.Role
                };
            });

        services.AddHttpClient("KeycloakClient");
        services.AddScoped<IKeycloakService, KeycloakService>();
        services.AddHttpContextAccessor();
        return services;
    }
}
