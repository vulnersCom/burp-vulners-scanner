package burp;

import com.mashape.unirest.http.Unirest;
import org.apache.http.HttpHost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class HttpClient {

    public static CloseableHttpAsyncClient createSSLClient() {
        return createSSLClient(null);
    }

    public static CloseableHttpAsyncClient createSSLClient(HttpHost proxy) {
        TrustStrategy acceptingTrustStrategy = new TrustStrategy() {

            @Override
            public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                return true;
            }
        };

        try {
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(null, acceptingTrustStrategy)
                    .build();

            HttpAsyncClientBuilder client = HttpAsyncClients.custom()
                    .setDefaultCookieStore(new BasicCookieStore())
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            if (proxy !=null) {
                client.setProxy(proxy);
            }

            return client.build();
        } catch (Exception e) {
            System.out.println("Could not create SSLContext");
            return null;
        }

    }
}
