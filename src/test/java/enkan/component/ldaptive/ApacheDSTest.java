package enkan.component.ldaptive;

import enkan.component.ldaptive.apacheds.LdapStandaloneServer;
import enkan.system.EnkanSystem;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ldaptive.LdapException;

import java.io.IOException;

import static enkan.util.BeanBuilder.builder;
import static org.assertj.core.api.Assertions.assertThat;

public class ApacheDSTest {
    private static LdapStandaloneServer server;
    @BeforeAll
    public static void setup() throws Exception {
        server = new LdapStandaloneServer();
    }

    @AfterAll
    public static void shutdown() throws Exception {
        if (server != null)
            server.stop();
    }

    @Test
    public void test() throws LdapException {
        EnkanSystem system = EnkanSystem.of(
                "ldap", builder(new LdapClient())
                        .set(LdapClient::setScheme, "ldap")
                        .set(LdapClient::setHost, "localhost")
                        .set(LdapClient::setPort, 10389)
                        .set(LdapClient::setSearchBase, "ou=users,dc=example,dc=com")
                        .build()
        );
        try {
            system.start();

            LdapClient ldap = system.getComponent("ldap");
            assertThat(ldap.search("kawasima", "password")).isTrue();
        } finally {
            system.stop();
        }
    }

    @Test
    public void ssl() throws LdapException {
        EnkanSystem system = EnkanSystem.of(
                "ldap", builder(new LdapClient())
                        .set(LdapClient::setScheme, "ldaps")
                        .set(LdapClient::setHost, "localhost")
                        .set(LdapClient::setPort, 10636)
                        .set(LdapClient::setSearchBase, "ou=users,dc=example,dc=com")
                        .set(LdapClient::setTruststorePath, "src/test/resources/clienttrust.jks")
                        .set(LdapClient::setTruststorePassword, "password")
                        .build()
        );
        try {
            system.start();

            LdapClient ldap = system.getComponent("ldap");
            assertThat(ldap.search("kawasima", "password")).isTrue();
        } finally {
            system.stop();
        }
    }
}
