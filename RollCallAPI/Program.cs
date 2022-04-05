using System.Text;
using System.Text.Json;
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

Dictionary<int, string> user = new Dictionary<int, string>();
user.Add(100, "123");
var currentToken = "";

bool CheckToken(HttpRequest request)
{
    var authHeader = request.Headers["Authorization"];
    return authHeader == currentToken;
}

app.MapPost("/login", async context =>
{
    InitializeUser();
    const string sqlSelectUser = "SELECT username, password, token FROM users;";
    var cmdSelectUser = new SqliteCommand(sqlSelectUser, con);
    SqliteDataReader sqliteDataReader;
    String output = "";
    sqliteDataReader = cmdSelectUser.ExecuteReader();
    while (sqliteDataReader.Read())
    {
        output = output + sqliteDataReader.GetValue(0) + " - " + sqliteDataReader.GetValue(1) + " - " +
                 sqliteDataReader.GetValue(2);
    }
    Console.WriteLine("================================");
    Console.WriteLine(output);
    var ctx = context;
    var req = context.Request;
    var body = "";
    using (var reader = new StreamReader(req.Body, Encoding.UTF8)) { body = await reader.ReadToEndAsync(); }
    var loginInfo = JsonSerializer.Deserialize<LoginInfo>(body);
    if (loginInfo != null)
    {
        if (!IsValid(loginInfo, 100))
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
    const int username = 100;
    const string password = "123";
    const int isAllowed = 1;
    var token = "faezestokenwithid" + username;
    const int firstLogin = 0;

    const string sqlInsertUser =
        "INSERT INTO users (username, password, isAllowed, token, firstLogin) VALUES (@username, @password, @isAllowed, @token, @firstLogin);";
    var cmdInsertUser = new SqliteCommand(sqlInsertUser, con);
    cmdInsertUser.Parameters.AddWithValue("@username", username);
    cmdInsertUser.Parameters.AddWithValue("@password", password);
    cmdInsertUser.Parameters.AddWithValue("@isAllowed", isAllowed);
    cmdInsertUser.Parameters.AddWithValue("@token", token);
    cmdInsertUser.Parameters.AddWithValue("@firstLogin", firstLogin);
    cmdInsertUser.Prepare();

    cmdInsertUser.ExecuteNonQuery();
}

bool IsValid(LoginInfo loginInfo, int userId)
{
    return loginInfo.username == userId && loginInfo.password == user[userId];
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

// public class Users
// {
//     public int username { get; set; }
//     public string password { get; set; }
//     public int isAllowed { get; set; }
//     public string token { get; set; }
//     public int firstLogin { get; set; }
// }