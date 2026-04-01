import java.io.*;
import java.beans.XMLDecoder;
import org.yaml.snakeyaml.Yaml;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DeserializationVulnerable {

    // Matches: java-objectinputstream-readobject
    public Object vulnerableObjectStream(InputStream input) throws Exception {
        return new ObjectInputStream(input).readObject();
    }

    // Matches: java-xmldecoder-readobject
    public Object vulnerableXmlDecoder(InputStream input) {
        return new XMLDecoder(input).readObject();
    }

    // Matches: java-snakeyaml-unsafe-load
    public Object vulnerableSnakeYaml(String input) {
        return new Yaml().load(input);
    }

    // Matches: java-jackson-defaulttyping
    public void vulnerableJackson() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
    }

    // Safe: use SafeConstructor
    public Object safeYamlLoad(String input) {
        return new Yaml(new org.yaml.snakeyaml.constructor.SafeConstructor()).load(input);
    }
}
