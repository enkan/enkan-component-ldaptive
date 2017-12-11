package enkan.component.ldaptive;

import enkan.component.ComponentLifecycle;
import enkan.component.SystemComponent;
import enkan.exception.UnreachableException;
import org.ldaptive.*;
import org.ldaptive.auth.*;
import org.ldaptive.ssl.KeyStoreCredentialConfig;
import org.ldaptive.ssl.SslConfig;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;

public class LdapClient extends SystemComponent {
    private String host = "localhost";
    private int port = 389;
    private String scheme = "ldap";
    private String user;
    private String password;
    private String searchBase = "";
    private String accountAttribute = "sAMAccountName";
    private String truststorePath;
    private String truststorePassword;
    private AuthMethod authMethod = AuthMethod.NONE;

    private Authenticator authenticator;

    private TrustManager[] createTrustManagers(String path, String password) throws IOException, KeyStoreException, CertificateException {
        try (InputStream is = new FileInputStream(path)) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, password.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            return tmf.getTrustManagers();
        } catch (NoSuchAlgorithmException e) {
            throw new UnreachableException(e);
        }
    }
    @Override
    protected ComponentLifecycle lifecycle() {
        return new ComponentLifecycle<LdapClient>() {
            @Override
            public void start(LdapClient component) {
                ConnectionConfig connConfig = new ConnectionConfig(component.getLdapUrl());
                if (authMethod == AuthMethod.SIMPLE) {
                    connConfig.setConnectionInitializer(new BindConnectionInitializer(component.user, new Credential(component.password)));
                }
                connConfig.setUseSSL(Objects.equals(component.scheme, "ldaps"));
                if (Objects.equals(component.scheme, "ldaps")) {
                    if (truststorePath != null) {
                        KeyStoreCredentialConfig credConfig = new KeyStoreCredentialConfig();
                        credConfig.setTrustStore("file:" + truststorePath);
                        credConfig.setTrustStorePassword(truststorePassword);
                        connConfig.setSslConfig(new SslConfig(credConfig));
                    }
                }
                ConnectionFactory connectionFactory = new DefaultConnectionFactory(connConfig);
                SearchDnResolver dnResolver = new SearchDnResolver(connectionFactory);
                dnResolver.setBaseDn(searchBase);
                dnResolver.setUserFilter(accountAttribute + "={user}");
                BindAuthenticationHandler authHandler = new BindAuthenticationHandler(connectionFactory);

                component.authenticator = new Authenticator(dnResolver, authHandler);
            }

            @Override
            public void stop(LdapClient component) {
            }
        };
    }

    public boolean search(String account, String password) throws LdapException {
        AuthenticationRequest request = new AuthenticationRequest(account, new Credential(password));
        AuthenticationResponse response = authenticator.authenticate(request);
        return response.getResult();
    }


    public String getLdapUrl() {
        return scheme + "://" + host + ":" + port;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setScheme(String scheme) {
        this.scheme = scheme;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    public void setAuthMethod(AuthMethod authMethod) {
        this.authMethod = authMethod;
    }

    public void setAccountAttribute(String accountAttribute) {
        this.accountAttribute = accountAttribute;
    }

    public enum AuthMethod {
        NONE("none"),
        SIMPLE("simple");

        private final String value;
        AuthMethod(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    public void setTruststorePath(String truststorePath) {
        this.truststorePath = truststorePath;
    }

    public void setTruststorePassword(String truststorePassword) {
        this.truststorePassword = truststorePassword;
    }
}
