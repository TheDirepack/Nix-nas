package org.zaproxy.addon.network;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.Cookie;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.URI;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.internal.client.apachev5.HttpSenderApache;
import org.zaproxy.addon.network.internal.client.apachev5.HttpSenderContextApache;
import org.zaproxy.addon.network.internal.ratelimit.NopRateLimiter;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;

public class CookieTransportTest {
    private static final class SessionUser extends User {
        final HttpState state = new HttpState();
        int processes;
        int polls;
        int checks;
        int renewals;

        SessionUser() {
            super(0, "fixture-user");
            state.addCookie(new Cookie("127.0.0.1", "sessionid", "valid", "/", null, false));
        }

        @Override
        public HttpState getCorrespondingHttpState() {
            return state;
        }

        @Override
        public void processMessageToMatchUser(HttpMessage message) {
            processes++;
            message.getRequestHeader().setHeader(HttpHeader.COOKIE, null);
        }

        @Override
        public void processMessageToMatchAuthenticatedSession(HttpMessage message) {
            polls++;
            message.getRequestHeader().setHeader(HttpHeader.COOKIE, null);
        }

        @Override
        public boolean isAuthenticated(HttpMessage message) {
            checks++;
            return message.getResponseHeader().getStatusCode() == 200;
        }

        @Override
        public void queueAuthentication(HttpMessage message) {
            renewals++;
            state.addCookie(new Cookie("127.0.0.1", "sessionid", "rotated", "/", null, false));
        }
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    private static HttpMessage send(
            HttpSenderApache sender, HttpSenderContextApache context, String url,
            String cookie, HttpRequestConfig config) throws Exception {
        HttpMessage message = new HttpMessage(new URI(url, false));
        message.setRequestingUser(context.getUser(message));
        message.getRequestHeader().setHeader(HttpHeader.COOKIE, cookie);
        sender.sendAndReceive(context, config, message, null);
        require(message.getRequestingUser() == context.getUser(message), "requesting user was removed");
        return message;
    }

    public static void main(String[] args) throws Exception {
        List<String> cookies = Collections.synchronizedList(new ArrayList<>());
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String cookie = exchange.getRequestHeaders().getFirst("Cookie");
            cookies.add(cookie);
            String path = exchange.getRequestURI().getPath();
            int status = 200;
            if (path.equals("/redirect")) {
                status = 302;
                exchange.getResponseHeaders().set("Location", "/private");
            } else if (path.equals("/reauth")) {
                status = cookie != null && cookie.contains("sessionid=rotated") ? 200 : 401;
            } else if (path.equals("/private")) {
                status = cookie != null && cookie.contains("sessionid=valid") ? 200 : 401;
            }
            if (status == 401) {
                exchange.getResponseHeaders().add("Set-Cookie", "sessionid=poison; Path=/");
            } else if (path.equals("/update")) {
                exchange.getResponseHeaders().add("Set-Cookie", "preference=updated; Path=/");
            }
            byte[] body = (status == 200 ? "owned private response" : "rejected").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        HttpSenderApache sender = new HttpSenderApache(
                BasicCookieStore::new, new ConnectionOptions(), new ClientCertificatesOptions(), () -> null);
        try {
            int[] counts = new int[3];
            sender.addListener(new HttpSenderListener() {
                @Override
                public int getListenerOrder() {
                    return 0;
                }

                @Override
                public void onHttpRequestSend(HttpMessage message, int initiator, HttpSender parent) {
                    counts[0]++;
                    require(message.getRequestingUser() != null, "listener lost the requesting user");
                }

                @Override
                public void onHttpResponseReceive(HttpMessage message, int initiator, HttpSender parent) {
                    counts[1]++;
                    require(message.getRequestingUser() != null, "response listener lost the requesting user");
                }
            });
            sender.setRateLimiter(new NopRateLimiter() {
                @Override
                public void throttle(HttpMessage message, int initiator) {
                    counts[2]++;
                }
            });
            String origin = "http://127.0.0.1:" + server.getAddress().getPort();
            SessionUser user = new SessionUser();
            HttpSenderContextApache context = sender.createContextImpl(null, HttpSender.ACTIVE_SCANNER_INITIATOR);
            context.setUser(user);
            HttpRequestConfig normal = HttpRequestConfig.builder().build();
            HttpRequestConfig probe = HttpRequestConfig.builder().setManageSession(false).setSoTimeout(12345).build();
            require(normal.isManageSession(), "session management is not enabled by default");
            HttpRequestConfig copied = HttpRequestConfig.builder(probe).build();
            require(!copied.isManageSession() && copied.getSoTimeout() == 12345, "config copy changed probe options");
            require(send(sender, context, origin + "/private", null, normal).getResponseHeader().getStatusCode() == 200,
                    "normal authenticated request lost its session");
            int processes = user.processes;
            int checks = user.checks;
            int requests = counts[0];
            int responses = counts[1];
            int throttles = counts[2];
            require(send(sender, context, origin + "/private", null, probe).getResponseHeader().getStatusCode() == 401,
                    "removed session cookie was restored");
            require(cookies.get(cookies.size() - 1) == null, "cookie-less probe acquired a cookie");
            String mutated = "sessionid=injected; preference=keep";
            require(send(sender, context, origin + "/private", mutated, probe).getResponseHeader().getStatusCode() == 401,
                    "mutated cookie was replaced by an authenticated session");
            require(mutated.equals(cookies.get(cookies.size() - 1)), "mutated cookie changed on the wire");
            HttpRequestConfig redirects = HttpRequestConfig.builder(probe).setFollowRedirects(true).build();
            int before = cookies.size();
            require(send(sender, context, origin + "/redirect", mutated, redirects).getResponseHeader().getStatusCode() == 401,
                    "redirect reenabled session management");
            require(cookies.size() == before + 2, "probe triggered hidden authentication retries");
            require(mutated.equals(cookies.get(before)) && mutated.equals(cookies.get(before + 1)),
                    "redirect altered probe cookies");
            require(user.processes == processes && user.checks == checks && user.renewals == 0,
                    "probe applied or renewed the shared session");
            require(counts[0] == requests + 4 && counts[1] == responses + 4 && counts[2] == throttles + 4,
                    "probe skipped listeners or rate limiting");
            require(user.state.getCookies().length == 1 && user.state.getCookies()[0].getValue().equals("valid"),
                    "probe response poisoned the shared session");
            require(send(sender, context, origin + "/private", null, normal).getResponseHeader().getStatusCode() == 200,
                    "probe disabled subsequent authenticated coverage");
            require(send(sender, context, origin + "/reauth", null, normal).getResponseHeader().getStatusCode() == 200,
                    "normal reauthentication stopped working");
            require(user.renewals == 1, "normal rejected request did not renew its session");
            send(sender, context, origin + "/update", null, normal);
            require(java.util.Arrays.stream(user.state.getCookies()).anyMatch(c -> c.getName().equals("preference")
                    && c.getValue().equals("updated")), "normal response no longer updates the user's cookie jar");
            HttpSenderContextApache polling = sender.createContextImpl(null, HttpSender.AUTHENTICATION_POLL_INITIATOR);
            polling.setUser(user);
            send(sender, polling, origin + "/update", null, normal);
            require(user.polls == 1, "normal authentication polling changed");
            System.out.println("Cookie transport: defaults, copies, authenticated coverage, removal, mutation, redirects, isolation, renewal, updates and polling pass");
        } finally {
            sender.close();
            server.stop(0);
        }
    }
}
