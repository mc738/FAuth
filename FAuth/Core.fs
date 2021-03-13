namespace FAuth.Core

open System
open System.Security.Cryptography
open System.Text.Json.Serialization

[<CLIMutable>]
type SecurityContext =
    { [<JsonPropertyName("key")>]
      Key: string
      [<JsonPropertyName("iterations")>]
      Iterations: int
      [<JsonPropertyName("hashSize")>]
      HashSize: int
      [<JsonPropertyName("connectionString")>]
      ConnectionString: string
      [<JsonPropertyName("appUrl")>]
      AppUrl: string }


module Utils =

    let getCryptoBytes length =
        let bytes: byte array = Array.zeroCreate length

        use rng = new RNGCryptoServiceProvider()

        rng.GetBytes(bytes)

        bytes

    let generateSalt = getCryptoBytes 16

    let generateKey =
        Convert.ToBase64String(getCryptoBytes 64)

    let saltFromString salt = Convert.FromBase64String salt
    
    let saltToString salt = Convert.ToBase64String salt

    let hashPassword context password (salt: byte array) =

        use pdkdf2 =
            new Rfc2898DeriveBytes(password + context.Key, salt, context.Iterations, HashAlgorithmName.SHA256)

        Convert.ToBase64String(pdkdf2.GetBytes(context.HashSize))

