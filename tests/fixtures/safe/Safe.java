import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;

public class Safe {
    private static final String PASSWORD_FIELD = "password";
    private final String password = System.getenv("DB_PASSWORD");

    public void find(Connection conn, String name) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        System.out.println("found " + name);
        new ProcessBuilder("tar", "czf", "/tmp/x.tgz", name).start();
        Runtime.getRuntime().exec("uptime");
        MessageDigest.getInstance("SHA-256");
    }
}
