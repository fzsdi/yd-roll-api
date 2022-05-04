using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;

var connectionStringBuilder = new SqliteConnectionStringBuilder();
connectionStringBuilder.DataSource = "./identifier.sqlite";
var cs = connectionStringBuilder.ConnectionString;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors();

var app = builder.Build();

app.UseCors(b => b .AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());

app.UseWebSockets();

const string secretKey = "eiszcvldytlfygojwfagruuluhftuhsn";
var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));
const string notValid = "Unauthenticated";
const string empty = "Empty";
const string issuer = "RollCallApi";
const string audience = "RollCallApi";

WebSocket webSocket = null;

var clients = new ConcurrentDictionary<string, WebSocket>();

app.Use(async (context, next) =>
{
    if (context.Request.Path == "/channel")
    {
        if (context.WebSockets.IsWebSocketRequest)
        {
            var token = context.Request.Query["token"][0];
            if (!ValidateToken(userToken: token))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            }
            else
            {
                webSocket = await context.WebSockets.AcceptWebSocketAsync();
                
                AddClient(webSocket);
                
                await ReceiveMessage(webSocket, async (result, buffer) =>
                {
                    switch (result.MessageType)
                    {
                        case WebSocketMessageType.Text:
                            Console.WriteLine($"Message received: {Encoding.UTF8.GetString(buffer, 0, result.Count)}");
                            return;
                        case WebSocketMessageType.Close:
                            var id = GetAllClients().FirstOrDefault(s => s.Value == webSocket).Key;
                            if (id == null) return;
                            GetAllClients().TryRemove(id, out var sock);
                            await sock!.CloseAsync(result.CloseStatus!.Value, result.CloseStatusDescription, CancellationToken.None);
                            return;
                    }
                });
            }
        }
        else
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
        }
    }
    else
    {
        await next(context);
    }
});

async Task ReceiveMessage(WebSocket socket, Action<WebSocketReceiveResult, byte[]> handleMessage)
{
    var buffer = new byte[1024 * 4];
    while (socket.State == WebSocketState.Open)
    {
        var result = await socket.ReceiveAsync(buffer: new ArraySegment<byte>(buffer),
            cancellationToken: CancellationToken.None);

        handleMessage(result, buffer);
    }
}

async Task SendMessage(WebSocket socket) {
    var buffer = Encoding.UTF8.GetBytes("Refresh");
    foreach (var client in GetAllClients())
    {
        if (socket.State == WebSocketState.Open && client.Value.State == WebSocketState.Open)
        {
            await client.Value.SendAsync(buffer, WebSocketMessageType.Text, true, CancellationToken.None);
        }
    }
}

ConcurrentDictionary<string, WebSocket> GetAllClients()
{
    return clients;
}

void AddClient(WebSocket socket)
{
    string connId = Guid.NewGuid().ToString();
    clients.TryAdd(connId, socket);
    Console.WriteLine("Connection added: " + connId);
}

bool ValidateToken([Optional] HttpRequest request, [Optional] string userToken)
{
    string jwtToken = request != null ? request.Headers["Authorization"] : userToken;

    var tokenHandler = new JwtSecurityTokenHandler();
    try
    {
        tokenHandler.ValidateToken(jwtToken, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = signingKey
        }, out _);
    }
    catch
    {
        return false;
    }

    return true;
}

bool IsAuthorized(HttpRequest request, int personId)
{
    string jwtToken = request.Headers["Authorization"];
    var handler = new JwtSecurityTokenHandler();
    var jwtSecurityToken = handler.ReadJwtToken(jwtToken);
    var role = jwtSecurityToken.Claims.First(claim => claim.Type == "role").Value;
    var sub = jwtSecurityToken.Claims.First(claim => claim.Type == "sub").Value;
    switch (role)
    {
        case "Admin":
            return true;
        case "User":
            return int.Parse(sub) == personId;
        default:
            return false;
    }
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
    if (loginInfo != null)
    {
        if (!IsValid(loginInfo, userId, userPass!, userSalt))
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync(notValid);
        }
        else
        {
            var userToken = GenerateJwt(userId, conn);
            var bytes = Encoding.UTF8.GetBytes(userToken);
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

string GenerateJwt(int userId, SqliteConnection conn)
{
    var role = IsAdmin(userId, conn);
    const int expiry = 60 * 24 * 1;
    var claims = new List<Claim>
    {
        new(JwtRegisteredClaimNames.Sub, userId.ToString()),
        new(JwtRegisteredClaimNames.Iss, issuer),
        new(JwtRegisteredClaimNames.Aud, audience),
        new("role", role)
    };
    
    var token = new JwtSecurityToken(
        claims:    claims,
        expires:   DateTime.UtcNow.AddMinutes(expiry),
        signingCredentials: new SigningCredentials(signingKey,
            SecurityAlgorithms.HmacSha256));
    
    return new JwtSecurityTokenHandler().WriteToken(token);
}

void InitializeUser(int username, string password)
{
    var userNameSql = 0;
    using var conn = new SqliteConnection(cs);
    conn.Open();
    var (hashedPass, salt) = SecurePassword(password: password);
    const int isAllowed = 0;
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
        "INSERT INTO users (username, password, isAllowed, firstLogin, salt) VALUES (@username, @password, @isAllowed, @firstLogin, @salt);";
    
    var cmdInsertUser = new SqliteCommand(sqlInsertUser, conn);
    
    cmdInsertUser.Parameters.AddWithValue("@username", username);
    cmdInsertUser.Parameters.AddWithValue("@password", hashedPass);
    cmdInsertUser.Parameters.AddWithValue("@isAllowed", isAllowed);
    cmdInsertUser.Parameters.AddWithValue("@firstLogin", firstLogin);
    cmdInsertUser.Parameters.AddWithValue("@salt", salt);
    
    cmdInsertUser.Prepare();
    cmdInsertUser.ExecuteNonQuery();
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
        var saltSize = password.Length;
        ranNumGenSalt = GenerateSaltUsingRanNumGen(saltSize);
    }
    var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
        password,
        ranNumGenSalt,
        KeyDerivationPrf.HMACSHA1,
        100000,
        256 / 8));
    
    return Tuple.Create(hashed, ranNumGenSalt);
}

byte[] GenerateSaltUsingRanNumGen(int saltSize)
{
    var random = new byte[saltSize];
    var rndGen = RandomNumberGenerator.Create();
    rndGen.GetBytes(random);
    return random;
}

bool IsValid(LoginInfo loginInfo, int userId, string userPass, byte[] userSalt)
{
    var (hashedPass, _) = SecurePassword(password: loginInfo.password!, salt: userSalt);
    return loginInfo.username == userId && hashedPass == userPass;
}

string IsAdmin(int id, SqliteConnection conn)
{
    var isAllowed = 0;
    const string sqlSelectUser = "SELECT isAllowed FROM users WHERE username=@username;";
    var cmdSelectPerson = new SqliteCommand(sqlSelectUser, conn);
    cmdSelectPerson.Parameters.AddWithValue("@username", id);
    var sqliteDataReaderUser = cmdSelectPerson.ExecuteReader();
    while (sqliteDataReaderUser.Read())
    {
        isAllowed = int.Parse(sqliteDataReaderUser.GetValue(0).ToString()!);
    }
    return isAllowed != 1 ? "User" : "Admin";
}

bool DoesExist(int targetedId, SqliteConnection conn)
{
    var personId = 0;
    const string sqlSelectPerson = "SELECT personId FROM persons WHERE personId=@personId AND deletedAt is null;";
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
    const string sqlSelectPersons = "SELECT personId, fullName, isPresent FROM persons WHERE deletedAt is null;";
    var cmdSelectPersons = new SqliteCommand(sqlSelectPersons, conn);
    var sqliteDataReaderPersons = cmdSelectPersons.ExecuteReader();
    while (sqliteDataReaderPersons.Read())
    {
        var id = int.Parse(sqliteDataReaderPersons.GetValue(0).ToString()!);
        var fullName = sqliteDataReaderPersons.GetValue(1).ToString();
        var isPresent = sqliteDataReaderPersons.GetValue(2).ToString() == "1";
        personsList.Add(new Person(id, fullName!, isPresent));
    }
    return personsList;
});

app.MapPost("/persons", async (Person person, HttpRequest request) =>
{
    if (!ValidateToken(request: request))
    {
        return Results.Unauthorized();
    }

    await using (var conn = new SqliteConnection(cs))
    {
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
    
        InitializeUser(person.Id, "7890");
 
        cmdInsertPerson.Prepare();
        cmdInsertPerson.ExecuteNonQuery();
    }
    
    if (webSocket != null)
        await SendMessage(webSocket);
    
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

app.MapPut("/persons/{id}", async (int id, Person person, HttpRequest request) =>
{
    if (!ValidateToken(request: request))
    {
        return Results.Unauthorized();
    }
    await using (var conn = new SqliteConnection(cs))
    {
        conn.Open();
        if (!IsAuthorized(request, person.Id))
        {
            return Results.StatusCode(405);
        }
        if (!DoesExist(id, conn))
        {
            return Results.NotFound();
        }
        var isPresent = person.IsPresent ? 1 : 0;
        const string sqlUpdatePerson =
            "UPDATE persons SET isPresent=@isPresent WHERE personId=@personId and deletedAt is null";
        var cmdUpdatePerson = new SqliteCommand(sqlUpdatePerson, conn);
        cmdUpdatePerson.Parameters.AddWithValue("@isPresent", isPresent);
        cmdUpdatePerson.Parameters.AddWithValue("@personId", id);
    
        cmdUpdatePerson.Prepare();
        cmdUpdatePerson.ExecuteNonQuery();
    }

    if (webSocket != null)
        await SendMessage(webSocket);

    return Results.Ok(person);
});

app.MapDelete("/persons/{id}", async (int id, HttpRequest request) =>
{
    if (!ValidateToken(request: request))
    {
        return Results.Unauthorized();
    }
    await using (var conn = new SqliteConnection(cs))
    {
        conn.Open();
        if (!DoesExist(id, conn))
        {
            return Results.NotFound();
        }
        var currentTime = DateTime.Now;
        const string sqlDeletePerson = "UPDATE persons SET deletedAt=@deletedAt WHERE personId=@personId and deletedAt is null";
        var cmdDeletePerson = new SqliteCommand(sqlDeletePerson, conn);
        cmdDeletePerson.Parameters.AddWithValue("@personId", id);
        cmdDeletePerson.Parameters.AddWithValue("@deletedAt", currentTime);
    
        cmdDeletePerson.Prepare();
        cmdDeletePerson.ExecuteNonQuery();
    }
    
    if (webSocket != null)
        await SendMessage(webSocket);
    
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