// Learn more about F# at http://docs.microsoft.com/dotnet/fsharp

open System
open FAuth.Core


[<EntryPoint>]
let main argv =
    
    printfn "Enter a password for `admin` user: "
    printf "> "
    
    let password = Console.ReadLine()
    
    let secretKey = Utils.generateKey
    let tokenKey = Utils.generateKey
       
    let ctx =  {
        Key = secretKey
        Iterations = 100000
        HashSize = 64
        ConnectionString = ""
        AppUrl = ""
    }
    
    let salt = Utils.generateSalt
    let hashedPassword = Utils.hashPassword ctx password salt
    
    printfn $"Secret key: {secretKey}"
    printfn $"Token key: {tokenKey}"
    printfn $"Admin password: {hashedPassword}"
    printfn $"Admin salt: {Utils.saltToString salt}"
    
    0 // return an integer exit code