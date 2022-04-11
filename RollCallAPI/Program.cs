using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Data.Sqlite;

const string cs = "Data Source=C:\\Practice\\RollCall\\RollCallAPI\\identifier.sqlite";

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors();

var app = builder.Build();

app.UseCors(b => b .AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());

const string notValid = "Unauthenticated";
const string empty = "Empty";

// app.Use((context, next) =>
// {
//     context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
//     context.Response.Headers.Add("Access-Control-Allow-Methods", "*");
//     context.Response.Headers.Add("Access-Control-Allow-Headers", "*");
//     return next();
// });

InitializeUser();
var currentToken = "";

bool CheckToken(HttpRequest request)
{
    var authHeader = request.Headers["Authorization"];
    return authHeader == currentToken;
}

app.MapPost("/login", async context =>
{
    await using var conn = new SqliteConnection(cs);
    conn.Open();
    var userId = 0;
    var userPass = "";
    var userSalt = new byte[] { };
    
    var ctx = context;
    var req = context.Request;
    string body;
    using (var reader = new StreamReader(req.Body, Encoding.UTF8)) { body = await reader.ReadToEndAsync(); }
    var loginInfo = JsonSerializer.Deserialize<LoginInfo>(body);
    
    const string sqlSelectUser = "SELECT username, password, salt FROM users where username=@username;";
    var cmdSelectUser = new SqliteCommand(sqlSelectUser, conn);
    cmdSelectUser.Parameters.AddWithValue("@username", loginInfo?.username);
    
    var sqliteDataReader = cmdSelectUser.ExecuteReader();
    while (sqliteDataReader.Read())
    {
        userId = int.Parse(sqliteDataReader.GetValue(0).ToString()!);
        userPass = sqliteDataReader.GetValue(1).ToString();
        userSalt = (byte[]) sqliteDataReader.GetValue(2);
    }
    conn.Close();
    if (loginInfo != null)
    {
        if (!IsValid(loginInfo, userId, userPass!, userSalt))
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync(notValid);
        }
        else
        {
            var userToken = GetUserToken(userId);
            var bytes = Encoding.UTF8.GetBytes(userToken);
            currentToken = userToken;
            ctx.Response.StatusCode = 200;
            await ctx.Response.Body.WriteAsync(bytes, 0, bytes.Length);
        }
    }
    else
    {
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsync(empty);
    }
});

string GetUserToken(int username)
{
    string token = "";
    using var conn = new SqliteConnection(cs);
    conn.Open();
    const string sqlSelectUserToken = "SELECT token FROM users WHERE username=@username";
    var cmdSelectUserToken = new SqliteCommand(sqlSelectUserToken, conn);
    cmdSelectUserToken.Parameters.AddWithValue("@username", username);
    var sqliteDataReaderUser = cmdSelectUserToken.ExecuteReader();
    while (sqliteDataReaderUser.Read())
    {
        token = sqliteDataReaderUser.GetValue(0).ToString()!;
    }
    return token;
}

void InitializeUser()
{
    var userNameSql = 0;
    using var conn = new SqliteConnection(cs);
    conn.Open();
    const int username = 100;
    const string password = "1234";
    var (hashedPass, salt) = SecurePassword(password);
    const int isAllowed = 1;
    var token = "faezestokenwithid" + username;
    const int firstLogin = 0;

    const string sqlSelectUser = "SELECT username FROM users WHERE username=@username";
    var cmdSelectUser = new SqliteCommand(sqlSelectUser, conn);
    cmdSelectUser.Parameters.AddWithValue("@username", username);
    var sqliteDataReaderUser = cmdSelectUser.ExecuteReader();
    while (sqliteDataReaderUser.Read())
    {
        userNameSql = int.Parse(sqliteDataReaderUser.GetValue(0).ToString()!);
    }
    if (userNameSql != 0)
    {
        return;
    }
    
    const string sqlInsertUser =
        "INSERT INTO users (username, password, isAllowed, token, firstLogin, salt) VALUES (@username, @password, @isAllowed, @token, @firstLogin, @salt);";
    
    var cmdInsertUser = new SqliteCommand(sqlInsertUser, conn);
    
    cmdInsertUser.Parameters.AddWithValue("@username", username);
    cmdInsertUser.Parameters.AddWithValue("@password", hashedPass);
    cmdInsertUser.Parameters.AddWithValue("@isAllowed", isAllowed);
    cmdInsertUser.Parameters.AddWithValue("@token", token);
    cmdInsertUser.Parameters.AddWithValue("@firstLogin", firstLogin);
    cmdInsertUser.Parameters.AddWithValue("@salt", salt);
    
    cmdInsertUser.Prepare();
    cmdInsertUser.ExecuteNonQuery();
    conn.Close();
}

Tuple<string, byte[]> SecurePassword(string password, [Optional] byte[]? salt)
{
    byte[] ranNumGenSalt;
    if (salt != null)
    {
        ranNumGenSalt = salt;
    }
    else
    {
        // Generate salt with csprng, RNGCryptoServiceProvider() is obsolete therefore I used RandomNumberGenerator.Create method
        var saltSize = password.Length; // TODO get the real length
        // var ranSalt = GenerateSaltUsingRandom(saltSize);
        ranNumGenSalt = GenerateSaltUsingRanNumGen(saltSize); // Either this or that
    }
    var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        password,
        ranNumGenSalt,
        KeyDerivationPrf.HMACSHA1,
        100000,
        256 / 8));
    
    return Tuple.Create(hashed, ranNumGenSalt);
}

byte[] GenerateSaltUsingRanNumGen(int saltSize) // TODO fix: lengths (pass and salt) do not match
{
    var random = new byte[saltSize];
    var rndGen = RandomNumberGenerator.Create();
    rndGen.GetBytes(random);
    // var randomSalt = Convert.ToBase64String(random);
    return random;
}

string GenerateSaltUsingRandom(int saltSize)
{
    const string alphanumeric = "abcdefghijklmnopqrstuvwxyz0123456789";
    const string specialCharacters = "!@#$%^&*~";
    
    var ran = new Random();
    var random = "";
    for (var i = 0; i <= saltSize-3; i++)
    {
        var fSalt = ran.Next(alphanumeric.Length);
        random += alphanumeric.ElementAt(fSalt);
    }
    for (var j = 0; j < 2; j++)
    {
        var sSalt = ran.Next(specialCharacters.Length);
        random += specialCharacters.ElementAt(sSalt);
    }
    return random;
}

bool IsValid(LoginInfo loginInfo, int userId, string userPass, byte[] userSalt)
{
    var (hashedPass, _) = SecurePassword(loginInfo.password!, userSalt);
    return loginInfo.username == userId && hashedPass == userPass;
}

bool DoesExist(int targetedId, SqliteConnection conn)
{
    var personId = 0;
    const string sqlSelectPerson = "SELECT personId FROM persons WHERE personId=@personId;";
    var cmdSelectPerson = new SqliteCommand(sqlSelectPerson, conn);
    cmdSelectPerson.Parameters.AddWithValue("@personId", targetedId);
    var sqliteDataReaderPerson = cmdSelectPerson.ExecuteReader();
    while (sqliteDataReaderPerson.Read())
    {
        personId = int.Parse(sqliteDataReaderPerson.GetValue(0).ToString()!);
    }
    return personId != 0;
}

app.MapGet("/persons", () =>
{
    var personsList = new List<Person>();
    using var conn = new SqliteConnection(cs);
    conn.Open();
    const string sqlSelectPersons = "SELECT personId, fullName, isPresent FROM persons;";
    var cmdSelectPersons = new SqliteCommand(sqlSelectPersons, conn);
    var sqliteDataReaderPersons = cmdSelectPersons.ExecuteReader();
    while (sqliteDataReaderPersons.Read())
    {
        var id = int.Parse(sqliteDataReaderPersons.GetValue(0).ToString()!);
        var fullName = sqliteDataReaderPersons.GetValue(1).ToString();
        var isPresent = sqliteDataReaderPersons.GetValue(2).ToString() == "1";
        personsList.Add(new Person(id, fullName!, isPresent));
    }
    conn.Close();
    return personsList;
});

app.MapPost("/persons", (Person person, HttpRequest request) =>
{
    if (!CheckToken(request))
    {
        return Results.Unauthorized();
    }
    using var conn = new SqliteConnection(cs);
    conn.Open();
    if (DoesExist(person.Id, conn))
    {
        return Results.Conflict();
    }
    var isPresent = person.IsPresent ? 1 : 0;
    const string sqlInsertPerson = "INSERT INTO persons (personId, fullName, isPresent, positionId) VALUES (@personId, @fullName, @isPresent, @positionId)";
    var cmdInsertPerson = new SqliteCommand(sqlInsertPerson, conn);
    cmdInsertPerson.Parameters.AddWithValue("@personId", person.Id);
    cmdInsertPerson.Parameters.AddWithValue("@fullName", person.FullName);
    cmdInsertPerson.Parameters.AddWithValue("@isPresent", isPresent);
    cmdInsertPerson.Parameters.AddWithValue("@positionId", 0);
    
    cmdInsertPerson.Prepare();
    cmdInsertPerson.ExecuteNonQuery();
    conn.Close();
    return Results.Created($"/Persons/{person.Id}", person);
});

app.MapGet("/persons/{id}", (int id) =>
{
    using var conn = new SqliteConnection(cs);
    conn.Open();
    if (!DoesExist(id, conn))
    {
        return Results.NotFound();
    }
    var person = new Person(0, "", false);
    const string sqlSelectPerson = "SELECT personId, fullName, isPresent FROM persons WHERE personId=@personId";
    var cmdSelectPerson = new SqliteCommand(sqlSelectPerson, conn);
    cmdSelectPerson.Parameters.AddWithValue("@personId", id);
    var sqliteDataReaderPerson = cmdSelectPerson.ExecuteReader();
    while (sqliteDataReaderPerson.Read())
    {
        var personId = int.Parse(sqliteDataReaderPerson.GetValue(0).ToString()!);
        var fullName = sqliteDataReaderPerson.GetValue(1).ToString();
        var isPresent = sqliteDataReaderPerson.GetValue(2).ToString() == "1";
        person.Id = personId;
        person.FullName = fullName!;
        person.IsPresent = isPresent;
    }
    
    return Results.Ok(person);
});

app.MapPut("/persons/{id}", (int id, Person person, HttpRequest request) =>
{
    using var conn = new SqliteConnection(cs);
    conn.Open();
    if (!CheckToken(request))
    {
        return Results.Unauthorized();
    }
    if (!DoesExist(id, conn))
    {
        return Results.NotFound();
    }
    var isPresent = person.IsPresent ? 1 : 0;
    const string sqlUpdatePerson =
        "UPDATE persons SET isPresent=@isPresent WHERE personId=@personId";
    var cmdUpdatePerson = new SqliteCommand(sqlUpdatePerson, conn);
    cmdUpdatePerson.Parameters.AddWithValue("@isPresent", isPresent);
    cmdUpdatePerson.Parameters.AddWithValue("@personId", id);
    
    cmdUpdatePerson.Prepare();
    cmdUpdatePerson.ExecuteNonQuery();
    conn.Close();
    
    return Results.Ok(person);
});

app.MapDelete("/persons/{id}", (int id, HttpRequest request) =>
{
    using var conn = new SqliteConnection(cs);
    conn.Open();
    if (!CheckToken(request))
    {
        return Results.Unauthorized();
    }
    if (!DoesExist(id, conn))
    {
        return Results.NotFound();
    }
    const string sqlDeletePerson = "DELETE FROM persons WHERE personId=@personId";
    var cmdDeletePerson = new SqliteCommand(sqlDeletePerson, conn);
    cmdDeletePerson.Parameters.AddWithValue("@personId", id);
    
    cmdDeletePerson.Prepare();
    cmdDeletePerson.ExecuteNonQuery();
    conn.Close();
    
    return Results.NoContent();
});

app.MapGet("/", () => "Hello, This is RollCall API.");

app.Run();

class Person
{
    public int Id { get; set; }
    public string FullName { get; set; }
    public bool IsPresent { get; set; }

    public Person(int id, string fullName, bool isPresent)
    {
        Id = id;
        FullName = fullName;
        IsPresent = isPresent;
    }
}

public class LoginInfo
{
    public int username { get; set; }
    public string? password { get; set; }
}