package restx.security;

import restx.factory.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public class DefaultRestxSessionCookieCodec implements RestxSessionCookieCodec {

    @Override
    public String encode(String cookie) {
        return Base64.getEncoder().encodeToString(cookie.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String decode(String cookie) {
        return new String(Base64.getDecoder().decode(cookie), StandardCharsets.UTF_8);
    }
}
