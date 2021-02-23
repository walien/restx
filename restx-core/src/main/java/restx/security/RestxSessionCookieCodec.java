package restx.security;

public interface RestxSessionCookieCodec {

    String encode(String cookie);

    String decode(String cookie);
}
