import java.math.BigInteger;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.util.Base64;

public class LabConfig {
    static final Path STATE = Path.of(".lab");
    static final String CLIENT = "java-lab";
    static final String APP = "http://127.0.0.1:18080";
    static final String IDP = "http://127.0.0.1:18081";
    static final String CALLBACK = APP + "/callback";
    static final String INTERNAL_IDP = "http://127.0.0.1:28081";

    public static void main(String[] args) throws Exception {
        String endpoint = args.length == 0 ? "127.0.0.1" : args[0];
        if (!endpoint.matches("[a-zA-Z0-9.-]+")) {
            throw new IllegalArgumentException("Укажите IPv4 или DNS-имя сервера");
        }
        Files.createDirectories(STATE);
        if (Files.exists(STATE.resolve("server.json")) || Files.exists(STATE.resolve("client.json"))
                || Files.exists(STATE.resolve("credentials.txt"))) {
            throw new IllegalStateException("Конфигурация .lab уже существует");
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
        KeyPair server = generator.generateKeyPair();
        KeyPair client = generator.generateKeyPair();
        Files.writeString(STATE.resolve("server.json"), """
            {
              "log": {"level":"debug","timestamp":true},
              "endpoints": [{
                "type":"wireguard","tag":"wg-server","system":false,
                "address":["10.77.0.1/24"],"listen_port":51820,"private_key":"%s",
                "peers":[{"public_key":"%s","allowed_ips":["10.77.0.2/32"]}]
              }],
              "outbounds":[{"type":"direct","tag":"local-java"}],
              "route":{"rules":[
                {"inbound":"wg-server","network":"tcp","source_ip_cidr":"10.77.0.2/32","port":8080,
                 "outbound":"local-java","override_address":"127.0.0.1","override_port":28080},
                {"inbound":"wg-server","network":"tcp","source_ip_cidr":"10.77.0.2/32","port":8081,
                 "outbound":"local-java","override_address":"127.0.0.1","override_port":28081},
                {"action":"reject"}
              ]}
            }
            """.formatted(privateKey(server), publicKey(client)), StandardOpenOption.CREATE_NEW);
        Files.writeString(STATE.resolve("client.json"), """
            {
              "log":{"level":"debug","timestamp":true},
              "inbounds":[
                {"type":"direct","tag":"browser-app","listen":"127.0.0.1","listen_port":18080,
                 "network":"tcp","override_address":"10.77.0.1","override_port":8080},
                {"type":"direct","tag":"browser-idp","listen":"127.0.0.1","listen_port":18081,
                 "network":"tcp","override_address":"10.77.0.1","override_port":8081}
              ],
              "endpoints":[{
                "type":"wireguard","tag":"wg-client","system":false,
                "address":["10.77.0.2/24"],"private_key":"%s",
                "peers":[{"address":"%s","port":51820,"public_key":"%s",
                          "allowed_ips":["10.77.0.1/32"]}]
              }],
              "route":{"final":"wg-client"}
            }
            """.formatted(privateKey(client), endpoint, publicKey(server)), StandardOpenOption.CREATE_NEW);
        Files.writeString(STATE.resolve("credentials.txt"), Lab.random() + "\n" + Lab.random() + "\n",
                StandardOpenOption.CREATE_NEW);
        System.out.println("Конфигурации VPN и данные OAuth созданы в .lab");
    }

    private static String privateKey(KeyPair pair) {
        return Base64.getEncoder().encodeToString(((XECPrivateKey) pair.getPrivate()).getScalar().orElseThrow());
    }

    private static String publicKey(KeyPair pair) {
        BigInteger coordinate = ((XECPublicKey) pair.getPublic()).getU();
        byte[] littleEndian = new byte[32];
        for (int i = 0; i < littleEndian.length; i++) {
            littleEndian[i] = coordinate.shiftRight(i * 8).byteValue();
        }
        return Base64.getEncoder().encodeToString(littleEndian);
    }
}
