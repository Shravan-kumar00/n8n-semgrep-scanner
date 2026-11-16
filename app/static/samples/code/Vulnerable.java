// Sample - intentionally vulnerable Java service (for scanner demos)
package demo;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.net.ssl.X509TrustManager;

public class Vulnerable {
    private static final String DB_PASSWORD = "Pr0duction#Pass";
    private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

    public ResultSet findUser(Connection conn, String name) throws Exception {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public void backup(String dir) throws Exception {
        Runtime.getRuntime().exec("tar czf /tmp/backup.tgz " + dir);
    }

    public Object restore(java.io.InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    public byte[] hash(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes());
    }

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    protected void configure(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
