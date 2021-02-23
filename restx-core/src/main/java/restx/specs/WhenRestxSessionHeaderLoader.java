package restx.specs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import restx.factory.Component;
import restx.security.RestxSessionCookieCodec;
import restx.security.RestxSessionCookieDescriptor;
import restx.security.Signer;

/**
 * @author fcamblor
 */
@Component
public class WhenRestxSessionHeaderLoader implements RestxSpecLoader.WhenHeaderLoader {

    private static final Logger logger = LoggerFactory.getLogger(WhenRestxSessionHeaderLoader.class);

    private final RestxSessionCookieDescriptor restxSessionCookieDescriptor;
    private final RestxSessionCookieCodec restxSessionCookieCodec;
    private final Signer signer;

    public WhenRestxSessionHeaderLoader(RestxSessionCookieDescriptor restxSessionCookieDescriptor,
                                        RestxSessionCookieCodec restxSessionCookieCodec,
                                        Signer signer) {
        this.restxSessionCookieDescriptor = restxSessionCookieDescriptor;
        this.restxSessionCookieCodec = restxSessionCookieCodec;
        this.signer = signer;
    }

    @Override
    public String detectionPattern() {
        return "$RestxSession:";
    }

    @Override
    public void loadHeader(String headerValue, WhenHttpRequest.Builder whenHttpRequestBuilder) {
        String sessionContent = headerValue.trim();

        if(whenHttpRequestBuilder.containsCookie(restxSessionCookieDescriptor.getCookieName())
                || whenHttpRequestBuilder.containsCookie(restxSessionCookieDescriptor.getCookieSignatureName())){
            logger.warn("Restx session cookie will be overwritten by {} special header !", detectionPattern());
        }

        String encodedSession = restxSessionCookieCodec.encode(sessionContent);
        whenHttpRequestBuilder.addCookie(restxSessionCookieDescriptor.getCookieName(), encodedSession);
        whenHttpRequestBuilder.addCookie(restxSessionCookieDescriptor.getCookieSignatureName(), signer.sign(encodedSession));
    }
}
