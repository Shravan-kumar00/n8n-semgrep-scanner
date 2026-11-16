// Sample - intentionally vulnerable C# service (for scanner demos)
using System.Diagnostics;
using System.Data.SqlClient;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

public class Vulnerable
{
    private const string ConnectionString = "Server=db;User Id=sa;Password=Sql$erver2026;";
    private string apiKey = "c4f1e2d3-a5b6-47c8-9d0e-1f2a3b4c5d6e";

    public void Find(SqlConnection conn, string name)
    {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
        cmd.ExecuteReader();
    }

    public void Convert(string file)
    {
        Process.Start("cmd.exe", "/c convert " + file);
    }

    public object Restore(System.IO.Stream s)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(s);
    }

    public HttpClient Client()
    {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
        return new HttpClient(handler);
    }

    public byte[] Hash(byte[] data) => MD5.Create().ComputeHash(data);
}
