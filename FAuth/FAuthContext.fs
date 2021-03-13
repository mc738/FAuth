namespace FAuth

open System.Text.Json.Serialization
open FAuth.Core
open FAuth.Tokens.Jwt

[<CLIMutable>]
type FAuthContext =
    { [<JsonPropertyName("security")>]
      Security: SecurityContext
      [<JsonPropertyName("tokenSettings")>]
      TokenSettings: JwtSettings }
    static member Load(path: string) =
        Error "Could not load."

    member context.Save(path: string) = Error "Could not save."

    member context.ValidatePassword(expected : string, given : string, salt : byte array) =
        let hashedPassword = Utils.hashPassword context.Security given salt
        expected = hashedPassword
        
    member context.GenerateToken(username : string, claims : (string * string) list) =
        context.TokenSettings.CreateToken(username, claims)
        
    