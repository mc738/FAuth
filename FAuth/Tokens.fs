namespace FAuth.Tokens

open System
open System.IdentityModel.Tokens.Jwt
open System.Security.Claims
open System.Text
open System.Text.Json.Serialization
open Microsoft.IdentityModel.Tokens

module Jwt =

    let createClaim issuer key value = Claim(key, value, issuer)
    
    let createClaims issuer (keyValues: (string * string) list) =
        keyValues |> List.map (fun (k, v) -> Claim(k, v, issuer))
    
    [<CLIMutable>]
    type JwtSettings =
        { [<JsonPropertyName("name")>]
          Name: string
          [<JsonPropertyName("secretKey")>]
          SecretKey: string
          [<JsonPropertyName("audience")>]
          Audience: string
          [<JsonPropertyName("tokenExpiry")>]
          TokenExpiry: float
          [<JsonPropertyName("issuer")>]
          Issuer: string }
        member settings.CreateToken(username, claims) =
            let claims =
                [ Claim("username", username, settings.Issuer) ]
                @ createClaims settings.Issuer claims

            let signedKey =
                SymmetricSecurityKey(Encoding.ASCII.GetBytes(settings.SecretKey))

            let (now: Nullable<DateTime>) = Nullable<DateTime>(DateTime.UtcNow)

            let expiryTime =
                Nullable<DateTime>(now.Value.AddMinutes(settings.TokenExpiry))

            let jwt =
                JwtSecurityToken
                    (settings.Issuer,
                     settings.Audience,
                     claims,
                     now,
                     expiryTime,
                     SigningCredentials(signedKey, SecurityAlgorithms.HmacSha256))

            let jwtSecurityHandler = JwtSecurityTokenHandler()
            jwtSecurityHandler.WriteToken(jwt)

        member settings.ValidateToken(token: string) =
            let tokenHandler = JwtSecurityTokenHandler()
            try
                let p = TokenValidationParameters()
                p.ValidateIssuerSigningKey <- true
                p.ValidateIssuer <- true
                p.ValidateAudience <- true
                p.ValidIssuer <- settings.Issuer
                p.ValidAudience <- settings.Audience
                p.IssuerSigningKey <- SymmetricSecurityKey(Encoding.ASCII.GetBytes(settings.SecretKey))
                
                match tokenHandler.ValidateToken(token, p) with
                | _ -> Ok()
            with
            | :? ArgumentNullException -> Error ""
            | :? ArgumentException -> Error ""
            | :? SecurityTokenEncryptionKeyNotFoundException -> Error ""
            | :? SecurityTokenDecryptionFailedException -> Error ""
            | :? SecurityTokenExpiredException -> Error ""
            | :? SecurityTokenInvalidAudienceException -> Error ""
            | :? SecurityTokenInvalidLifetimeException -> Error ""
            | :? SecurityTokenInvalidSignatureException -> Error ""
            | :? SecurityTokenException -> Error ""
