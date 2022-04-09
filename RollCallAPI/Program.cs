using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Data.Sqlite;

const string cs = "Data Source=C:\\Practice\\RollCall\\RollCallAPI\\identifier.sqlite";
const string sqlVersion = "SELECT SQLITE_VERSION()";
using var con = new SqliteConnection(cs);
con.Open();
using var cmd = new SqliteCommand(sqlVersion, con);
var version = cmd.ExecuteScalar()?.ToString(); /* There are queries which return only a scalar value.
                                                    In our case, we want a simple string specifying the version of the database.
                                                    The ExecuteScalar is used in such situations.
                                                    We avoid the overhead of using more complex objects. */
Console.WriteLine($"SQLite version: {version}");
con.Close();

var builder = WebApplication.CreateBuilder(args);
var repo = new PersonRepository();
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
    SqliteDataReader sqliteDataReader;
    using var conn = new SqliteConnection(cs);
    conn.Open();
    var userId = 0;
    var userPass = "";
    var userSalt = new byte[] { };
    
    var ctx = context;
    var req = context.Request;
    var body = "";
    using (var reader = new StreamReader(req.Body, Encoding.UTF8)) { body = await reader.ReadToEndAsync(); }
    var loginInfo = JsonSerializer.Deserialize<LoginInfo>(body);
    
    const string sqlSelectUser = "SELECT username, password, salt FROM users where username=@username;";
    var cmdSelectUser = new SqliteCommand(sqlSelectUser, conn);
    cmdSelectUser.Parameters.AddWithValue("@username", loginInfo.username);
    
    var output = "";
    sqliteDataReader = cmdSelectUser.ExecuteReader();
    while (sqliteDataReader.Read())
    {
        userId = int.Parse(sqliteDataReader.GetValue(0).ToString());
        userPass = sqliteDataReader.GetValue(1).ToString();
        // var userSaltStr = sqliteDataReader.GetValue(2).ToString();
        userSalt = (byte[]) sqliteDataReader.GetValue(2);
        output = output + sqliteDataReader.GetValue(0) + " - " + sqliteDataReader.GetValue(1) + " - " +
                 sqliteDataReader.GetValue(2);
    }
    conn.Close();
    if (loginInfo != null)
    {
        if (!IsValid(loginInfo, userId, userPass, userSalt))
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync(notValid);
        }
        else
        {
            var userToken = "faezestokenwithid" + loginInfo.username;
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

void InitializeUser()
{
    using var conn = new SqliteConnection(cs);
    conn.Open();
    const int username = 100;
    const string password = "1234";
    var (hashedPass, salt) = SecurePassword(password, null);
    const int isAllowed = 1;
    var token = "faezestokenwithid" + username;
    const int firstLogin = 0;
    
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

Tuple<string, byte[]> SecurePassword(string password, byte[]? salt)
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
        KeyDerivationPrf.HMACSHA256,
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
    var (hashedPass, salt) = SecurePassword(loginInfo.password, userSalt);
    Console.WriteLine("=====HASHED PASS FROM METHOD=====");
    Console.WriteLine(hashedPass);
    Console.WriteLine("=====HASHED PASS FROM DB=====");
    Console.WriteLine(userPass);
    // Console.WriteLine(Convert.ToBase64String(userSalt));
    // Console.WriteLine(Convert.ToBase64String(salt));
    return loginInfo.username == userId && hashedPass == userPass;
}

app.MapGet("/persons", () => repo.GetAll());

app.MapPost("/persons", (Person person, HttpRequest request) =>
{
    if (!CheckToken(request))
    {
        return Results.Unauthorized();
    }
    if (repo.GetById(person.Id) != null)
    {
        return Results.Conflict();
    }
    repo.Add(person);
    return Results.Created($"/Persons/{person.Id}", person);
});

app.MapGet("/persons/{id}", (int id) =>
{
    var person = repo.GetById(id);
    return person == null ? Results.NotFound() : Results.Ok(person);
});

app.MapPut("/persons/{id}", (int id, Person person, HttpRequest request) =>
{
    if (!CheckToken(request))
    {
        return Results.Unauthorized();
    }
    if (repo.GetById(id) == null)
    {
        return Results.NotFound();
    }
    repo.Update(person);
    return Results.Ok(person);
});

app.MapDelete("/persons/{id}", (int id, HttpRequest request) =>
{
    if (!CheckToken(request))
    {
        return Results.Unauthorized();
    }
    if (repo.GetById(id) == null)
    {
        return Results.NotFound();
    }
    repo.Delete(id);
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

class PersonRepository
{
    private readonly Dictionary<int, Person> _persons = new()
    {
        {1, new Person(1, "Faeze", true)},
        {2, new Person(2, "Sara", false)},
        {3, new Person(3, "Amir", true)}
    };

    public IEnumerable<Person> GetAll() => _persons.Values;

    public Person? GetById(int id) => _persons.ContainsKey(id) ? _persons[id] : null;  
    public void Add(Person person) => _persons.Add(person.Id, person);
    public void Update(Person person) => _persons[person.Id] = person;
    public void Delete(int id) => _persons.Remove(id);
}

public class LoginInfo
{
    public int username { get; set; }
    public string? password { get; set; }
}