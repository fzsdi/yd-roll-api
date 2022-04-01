namespace RollCallAPI;

public class Test
{
    public int Age { get; set; }
    private int height = 0;
    private string name = null;

    public string Name()
    {
        return name ?? "";
    }

    public Test GetOld()
    {
        Age++;
        return this;
    }

    public Test GetYoung()
    {
        Age--;
        return this;
    }

    public static Test StaticMethod()
    {
        return new Test();
    }
}

public static class TestExtensions
{
    public static void GetOld(this WebApplication test)
    {
        
    }
}