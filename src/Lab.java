import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

public final class Lab {
    private static final String USER = "student";
    private static final String SCOPE = "lab.read";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern TOKEN_JSON = Pattern.compile("\"access_token\":\"([A-Za-z0-9_-]{43})\"");
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    private final Expiring<Login> logins = new Expiring<>(300);
    private final Expiring<Consent> consents = new Expiring<>(300);
    private final Expiring<String> codes = new Expiring<>(60);
    private final Expiring<String> tokens = new Expiring<>(300);
    private final Expiring<String> sessions = new Expiring<>(1800);
    private final byte[] passwordHash;
    private final String clientAuth;

    private record Login(String state, String verifier) {}
    private record Consent(String state, String challenge) {}

    private Lab(String password, String secret) {
        passwordHash = sha256(password);
        clientAuth = "Basic " + Base64.getEncoder().encodeToString(
                (LabConfig.CLIENT + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {
        List<String> credentials = Files.readAllLines(LabConfig.STATE.resolve("credentials.txt"));
        Lab lab = new Lab(credentials.get(0), credentials.get(1));
        start("APP", 28080, lab::app);
        start("OAUTH", 28081, lab::oauth);
    }

    private static void start(String label, int port, com.sun.net.httpserver.HttpHandler handler)
            throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            boolean app = port == 28080;
            boolean backchannel = path.equals("/oauth/token") || path.equals("/oauth/profile");
            String authority = app ? "127.0.0.1:18080" : backchannel ? "127.0.0.1:28081" : "127.0.0.1:18081";
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("Referrer-Policy", "no-referrer");
            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            exchange.getResponseHeaders().set("Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
                            + (app ? "" : " " + LabConfig.APP));
            try {
                if (!authority.equals(exchange.getRequestHeaders().getFirst("Host"))) {
                    send(exchange, 421, "text/plain", "Недопустимый адрес сервиса");
                    return;
                }
                handler.handle(exchange);
            } catch (IllegalArgumentException e) {
                send(exchange, 400, "text/plain", "Некорректный запрос");
            } finally {
                exchange.close();
            }
        });
        server.start();
        System.out.printf("[%s] Listening on 127.0.0.1:%d%n", label, port);
    }

    private void app(HttpExchange x) throws IOException {
        String path = x.getRequestURI().getPath();
        if ((path.equals("/logout") && !method(x, "POST"))
                || (!path.equals("/logout") && !method(x, "GET"))) {
            x.getResponseHeaders().set("Allow", path.equals("/logout") ? "POST" : "GET");
            send(x, 405, "text/plain", "Method not allowed");
            return;
        }
        switch (path) {
            case "/" -> page(x, 200, "Главная", "Страница 1. Учебное веб-приложение работает.",
                    "<p><a href='/notes'>Открыть страницу 2</a></p>");
            case "/notes" -> page(x, 200, "Заметки", "Страница 2. Здесь размещены учебные заметки.",
                    "<p><a href='/'>Вернуться на главную</a></p>");
            case "/private" -> {
                String logoutToken = sessions.get(cookie(x, "lab_session"));
                if (logoutToken != null) {
                    page(x, 200, "Личный кабинет", "Доступ разрешён. Пользователь: student.",
                            """
                            <form method='post' action='/logout'>
                              <input type='hidden' name='csrf' value='%s'><button>Выйти</button>
                            </form>
                            """.formatted(logoutToken));
                } else {
                    page(x, 401, "Требуется вход", "Личный кабинет доступен после авторизации.",
                            "<a class='button' href='/login'>Войти через OAuth 2.0</a>");
                }
            }
            case "/login" -> {
                Login login = new Login(random(), random());
                setCookie(x, "lab_login", logins.add(login), "/", 300);
                redirect(x, LabConfig.IDP + "/oauth/authorize?" + encode(Map.of(
                        "response_type", "code", "client_id", LabConfig.CLIENT,
                        "redirect_uri", LabConfig.CALLBACK, "scope", SCOPE, "state", login.state(),
                        "code_challenge_method", "S256", "code_challenge", challenge(login.verifier()))));
            }
            case "/callback" -> callback(x);
            case "/logout" -> {
                String session = cookie(x, "lab_session");
                String logoutToken = sessions.get(session);
                if (logoutToken == null || !logoutToken.equals(form(x).get("csrf"))) {
                    send(x, 403, "text/plain", "Недействительный запрос выхода");
                    return;
                }
                sessions.remove(session);
                setCookie(x, "lab_session", "", "/", 0);
                redirect(x, "/private");
            }
            default -> page(x, 404, "Страница не найдена", "", "");
        }
    }

    private void callback(HttpExchange x) throws IOException {
        Map<String, String> query = parse(x.getRequestURI().getRawQuery());
        Login login = logins.remove(cookie(x, "lab_login"));
        setCookie(x, "lab_login", "", "/", 0);
        if (login == null || !login.state().equals(query.get("state"))) {
            page(x, 400, "Вход не завершён", "Запрос входа истёк или не прошёл проверку state.", "");
            return;
        }
        if (query.containsKey("error")) {
            page(x, 403, "Доступ отклонён", "Приложение не получило разрешение.", "<a href='/login'>Повторить вход</a>");
            return;
        }
        String code = query.getOrDefault("code", "");
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(LabConfig.INTERNAL_IDP + "/oauth/token"))
                    .timeout(Duration.ofSeconds(5)).header("Authorization", clientAuth)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(encode(Map.of(
                            "grant_type", "authorization_code", "code", code,
                            "redirect_uri", LabConfig.CALLBACK, "code_verifier", login.verifier())))).build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            var match = TOKEN_JSON.matcher(response.body());
            if (response.statusCode() != 200 || !match.find()) throw new IOException("Token exchange failed");
            HttpRequest profile = HttpRequest.newBuilder(URI.create(LabConfig.INTERNAL_IDP + "/oauth/profile"))
                    .timeout(Duration.ofSeconds(5)).header("Authorization", "Bearer " + match.group(1)).build();
            HttpResponse<String> user = http.send(profile, HttpResponse.BodyHandlers.ofString());
            if (user.statusCode() != 200 || !USER.equals(user.body())) throw new IOException("Profile check failed");
            sessions.remove(cookie(x, "lab_session"));
            setCookie(x, "lab_session", sessions.add(random()), "/", 1800);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            page(x, 502, "Сервис авторизации недоступен", "Повторите вход.", "");
            return;
        } catch (IOException e) {
            page(x, 502, "Ошибка авторизации", "Не удалось проверить разрешение OAuth 2.0.", "");
            return;
        }
        System.out.println("[APP] Valid state; exchanged code; profile verified; session created for student");
        redirect(x, "/private");
    }

    private void oauth(HttpExchange x) throws IOException {
        switch (x.getRequestMethod() + " " + x.getRequestURI().getPath()) {
            case "GET /oauth/authorize" -> authorize(x);
            case "POST /oauth/decision" -> decision(x);
            case "POST /oauth/token" -> token(x);
            case "GET /oauth/profile" -> {
                String authorization = x.getRequestHeaders().getFirst("Authorization");
                if (authorization == null || !authorization.startsWith("Bearer ")
                        || !USER.equals(tokens.get(authorization.substring(7)))) {
                    x.getResponseHeaders().set("WWW-Authenticate", "Bearer");
                    jsonError(x, 401, "invalid_token");
                } else {
                    send(x, 200, "text/plain", USER);
                }
            }
            default -> send(x, 404, "text/plain", "Ресурс не найден");
        }
    }

    private void authorize(HttpExchange x) throws IOException {
        Map<String, String> query = parse(x.getRequestURI().getRawQuery());
        String state = query.getOrDefault("state", "");
        String challenge = query.getOrDefault("code_challenge", "");
        if (!LabConfig.CLIENT.equals(query.get("client_id"))
                || !LabConfig.CALLBACK.equals(query.get("redirect_uri"))) {
            jsonError(x, 400, "invalid_request");
            return;
        }
        if (!state.matches("[A-Za-z0-9_-]{43}") || !challenge.matches("[A-Za-z0-9_-]{43}")
                || !"S256".equals(query.get("code_challenge_method"))
                || !"code".equals(query.get("response_type")) || !SCOPE.equals(query.get("scope"))) {
            jsonError(x, 400, "invalid_request");
            return;
        }
        String ticket = consents.add(new Consent(state, challenge));
        consentForm(x, 200, ticket, "");
    }

    private void consentForm(HttpExchange x, int status, String ticket, String message) throws IOException {
        setCookie(x, "lab_consent", ticket, "/oauth/decision", 300);
        render(x, status, "Сервер авторизации", "Разрешение для java-lab",
                "Приложение запрашивает право lab.read для доступа к учебному профилю.",
                """
                <form method='post' action='/oauth/decision'>
                  <input type='hidden' name='ticket' value='%s'>
                  <label>Пользователь<input name='username' autocomplete='username'></label>
                  <label>Пароль<input name='password' type='password' autocomplete='current-password'></label>
                  <button name='decision' value='allow'>Войти и разрешить</button>
                  <button class='secondary' name='decision' value='deny'>Отклонить</button>
                </form><p role='status'>%s</p>
                """.formatted(ticket, message), "");
    }

    private void decision(HttpExchange x) throws IOException {
        Map<String, String> input = form(x);
        String ticket = cookie(x, "lab_consent");
        Consent consent = consents.get(ticket);
        if (consent == null || !ticket.equals(input.get("ticket"))) {
            jsonError(x, 400, "invalid_request");
            return;
        }
        boolean denied = "deny".equals(input.get("decision"));
        if (!denied && (!"allow".equals(input.get("decision")) || !USER.equals(input.get("username"))
                || !MessageDigest.isEqual(passwordHash, sha256(input.getOrDefault("password", ""))))) {
            consentForm(x, 401, ticket, "Проверьте имя пользователя и пароль.");
            return;
        }
        if (consents.remove(ticket) == null) {
            jsonError(x, 400, "invalid_request");
            return;
        }
        setCookie(x, "lab_consent", "", "/oauth/decision", 0);
        var result = denied ? Map.of("error", "access_denied", "state", consent.state())
                : Map.of("code", codes.add(consent.challenge()), "state", consent.state());
        if (!denied) System.out.println("[OAUTH] Authorization code issued (scope=lab.read, PKCE=S256)");
        redirect(x, LabConfig.CALLBACK + "?" + encode(result));
    }

    private void token(HttpExchange x) throws IOException {
        String authorization = x.getRequestHeaders().getFirst("Authorization");
        if (authorization == null || !MessageDigest.isEqual(clientAuth.getBytes(StandardCharsets.UTF_8),
                authorization.getBytes(StandardCharsets.UTF_8))) {
            x.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"java-lab\"");
            jsonError(x, 401, "invalid_client");
            return;
        }
        Map<String, String> input = form(x);
        if (!"authorization_code".equals(input.get("grant_type"))) {
            jsonError(x, 400, "unsupported_grant_type");
            return;
        }
        String verifier = input.getOrDefault("code_verifier", "");
        String code = input.getOrDefault("code", "");
        String expected = codes.get(code);
        if (!LabConfig.CALLBACK.equals(input.get("redirect_uri")) || expected == null
                || !verifier.matches("[A-Za-z0-9._~-]{43,128}") || !expected.equals(challenge(verifier))
                || codes.remove(code) == null) {
            jsonError(x, 400, "invalid_grant");
            return;
        }
        String value = tokens.add(USER);
        System.out.println("[OAUTH] PKCE verified; one-time code exchanged; access token issued");
        x.getResponseHeaders().set("Pragma", "no-cache");
        send(x, 200, "application/json", """
                {"access_token":"%s","token_type":"Bearer","expires_in":300,"scope":"lab.read"}
                """.formatted(value));
    }

    private static Map<String, String> form(HttpExchange x) throws IOException {
        String type = x.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !type.split(";", 2)[0].trim().equalsIgnoreCase("application/x-www-form-urlencoded")) {
            throw new IllegalArgumentException("Expected form data");
        }
        byte[] bytes = x.getRequestBody().readNBytes(4097);
        if (bytes.length > 4096) throw new IllegalArgumentException("Form too large");
        return parse(new String(bytes, StandardCharsets.UTF_8));
    }

    private static Map<String, String> parse(String form) {
        Map<String, String> values = new HashMap<>();
        if (form == null || form.isEmpty()) return values;
        for (String pair : form.split("&")) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            if (values.putIfAbsent(key, value) != null) throw new IllegalArgumentException("Duplicate field");
        }
        return values;
    }

    private static String encode(Map<String, String> values) {
        StringJoiner query = new StringJoiner("&");
        values.forEach((key, value) -> query.add(key + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)));
        return query.toString();
    }

    private static boolean method(HttpExchange x, String method) {
        return method.equals(x.getRequestMethod());
    }

    private static String cookie(HttpExchange x, String name) {
        for (String header : x.getRequestHeaders().getOrDefault("Cookie", List.of())) {
            for (String part : header.split(";")) {
                String[] pair = part.trim().split("=", 2);
                if (pair.length == 2 && name.equals(pair[0])) return pair[1];
            }
        }
        return "";
    }

    private static void setCookie(HttpExchange x, String name, String value, String path, int ttl) {
        x.getResponseHeaders().add("Set-Cookie",
                "%s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Lax".formatted(name, value, path, ttl));
    }

    private static void page(HttpExchange x, int status, String title, String body, String extra) throws IOException {
        render(x, status, "Учебное веб-приложение", title, body, extra, """
            <nav><a href='/'>Главная</a><a href='/notes'>Заметки</a><a href='/private'>Личный кабинет</a></nav>
            """);
    }

    private static void render(HttpExchange x, int status, String label, String title, String body,
                               String extra, String nav) throws IOException {
        send(x, status, "text/html", """
            <!doctype html><html lang='ru'><meta charset='utf-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1'>
            <title>%s</title><style>
            *{box-sizing:border-box}body{margin:0;background:#eef4f3;color:#153031;font:17px/1.5 system-ui,sans-serif}
            main{max-width:700px;margin:7vh auto;padding:30px 34px;background:#fff;border-radius:14px}
            header{font-size:14px;color:#3d5758}nav{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px}
            h1{font-size:36px;line-height:1.15;margin:24px 0 14px}a{color:#07685c}a.button,button{display:inline-block;
            padding:9px 14px;background:#07685c;color:#fff;text-decoration:none;border:0;border-radius:6px;font:inherit}
            button{cursor:pointer}button.secondary{background:#e0ece9;color:#153031}
            label{display:block;margin:12px 0}input:not([type=hidden]){display:block;width:min(100%%,340px);
            padding:7px 9px;border:1px solid #718b8a;border-radius:6px;font:inherit}
            @media (max-width:720px){main{margin:12px;padding:18px}}
            </style><main><header>%s</header>%s<h1>%s</h1><p>%s</p>%s</main></html>
            """.formatted(title, label, nav, title, body, extra));
    }

    private static void redirect(HttpExchange x, String url) throws IOException {
        x.getResponseHeaders().set("Location", url);
        x.sendResponseHeaders(303, -1);
    }

    private static void jsonError(HttpExchange x, int status, String error) throws IOException {
        send(x, status, "application/json", "{\"error\":\"" + error + "\"}");
    }

    private static void send(HttpExchange x, int status, String mediaType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type", mediaType + "; charset=utf-8");
        x.sendResponseHeaders(status, bytes.length);
        x.getResponseBody().write(bytes);
    }

    static String random() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String challenge(String verifier) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(verifier));
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class Expiring<T> {
        private record Entry<T>(T value, long expires) {}
        private final ConcurrentMap<String, Entry<T>> entries = new ConcurrentHashMap<>();
        private final long ttl;

        Expiring(long seconds) {
            ttl = TimeUnit.SECONDS.toNanos(seconds);
        }

        String add(T value) {
            long now = System.nanoTime();
            entries.entrySet().removeIf(entry -> entry.getValue().expires() - now <= 0);
            String key = random();
            entries.put(key, new Entry<>(value, now + ttl));
            return key;
        }

        T get(String key) {
            return valid(entries.get(key));
        }

        T remove(String key) {
            return valid(entries.remove(key));
        }

        private T valid(Entry<T> entry) {
            return entry != null && entry.expires() - System.nanoTime() > 0 ? entry.value() : null;
        }
    }
}
