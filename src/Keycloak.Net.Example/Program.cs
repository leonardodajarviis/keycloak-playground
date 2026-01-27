using Keycloak.Net.Example.Models;
using Keycloak.Net.Extensions;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger with JWT Bearer authentication support
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Keycloak.Net Example API",
        Version = "v1",
        Description = "Demo API showing Keycloak authentication integration"
    });

    // Add JWT Bearer authentication to Swagger
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token in the format: Bearer {your token}"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Configure Keycloak authentication
builder.Services.AddKeycloakAuthentication(builder.Configuration);
// Configure authorization policies
builder.Services.AddAuthorization();
builder.Services.AddKeycloakUserProvider<User, string>();


var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// Add authentication middleware (required for [Authorize] to work)
app.UseAuthentication();
app.UseKeycloakAuth();


// Authorization middleware must come after authentication
app.UseAuthorization();

app.MapControllers();

app.Run();
