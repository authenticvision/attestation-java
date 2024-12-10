package example;

import org.jetbrains.annotations.NotNull;

import java.time.Instant;

public class TokenExpiredException extends Exception {
    public TokenExpiredException(@NotNull Instant expirationDate) {
        super("Token expired at " + expirationDate.toString());
    }
}
