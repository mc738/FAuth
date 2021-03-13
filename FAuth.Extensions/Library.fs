namespace FAuth.Extensions

open System
open System.Text
open FAuth.Tokens.Jwt
open Microsoft.AspNetCore.Authentication
open Microsoft.AspNetCore.Authentication.JwtBearer
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Cors.Infrastructure
open Microsoft.Extensions.DependencyInjection
open FAuth
open Microsoft.IdentityModel.Tokens

[<AutoOpen>]
module AspNetCore =
    
    let private authenticationOptions (o : AuthenticationOptions) =
        o.DefaultAuthenticateScheme <- JwtBearerDefaults.AuthenticationScheme
        o.DefaultChallengeScheme <- JwtBearerDefaults.AuthenticationScheme
    
    let private getJwtBearerOptions (settings: JwtSettings) (cfg: JwtBearerOptions) =
        //cfg.SaveToken <- true
        //cfg.IncludeErrorDetails <- true
        //cfg.Authority <- settings.Issuer
        //cfg.Audience <- settings.Audience
        cfg.RequireHttpsMetadata <- false

        let p = TokenValidationParameters()
        p.ValidateIssuerSigningKey <- true
        p.ValidateIssuer <- true
        p.ValidateAudience <- true
        p.ValidIssuer <- settings.Issuer
        p.ValidAudience <- settings.Audience
        p.IssuerSigningKey <- SymmetricSecurityKey(Encoding.ASCII.GetBytes(settings.SecretKey))

        cfg.TokenValidationParameters <- p

    let configureCors (ctx : FAuthContext) (builder : CorsPolicyBuilder) =
        builder.WithOrigins(ctx.Security.AppUrl)
               .AllowAnyMethod()
               .AllowAnyHeader()
               |> ignore
    
    type IServiceCollection with

        member builder.AddFAuth(ctx: FAuthContext) =
            builder
                .AddAuthentication()
                .AddJwtBearer(Action<JwtBearerOptions>(getJwtBearerOptions ctx.TokenSettings))
            |> ignore

    type IApplicationBuilder with
    
        member builder.AddFAuth(ctx : FAuthContext) =
            builder
                .UseCors(configureCors ctx)
                .UseAuthentication()