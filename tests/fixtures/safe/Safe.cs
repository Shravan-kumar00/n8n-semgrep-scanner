using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;

public class Safe
{
    private readonly string password = System.Environment.GetEnvironmentVariable("DB_PASSWORD");
    private const string PasswordField = "password";

    public void Find(SqlConnection conn, string name)
    {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        Process.Start("notepad.exe");
        SHA256.Create();
    }
}
