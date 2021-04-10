namespace FAuth

open System.Text.Json.Serialization
open FAuth.Core
open FAuth.Tokens.Jwt
//open 

[<CLIMutable>]
type FAuthContext =
    { [<JsonPropertyName("security")>]
      Security: SecurityContext
      [<JsonPropertyName("tokenSettings")>]
      TokenSettings: JwtSettings }

    member context.HashPassword(password : string) (salt : string) =
        Utils.saltFromString salt
        |> Utils.hashPassword context.Security password
    
    member context.ValidatePassword(expected : string, given : string, salt : byte array) =
        let hashedPassword = Utils.hashPassword context.Security given salt
        expected = hashedPassword
        
    member context.GenerateToken(username : string, claims : (string * string) list) =
        context.TokenSettings.CreateToken(username, claims)
        
    