package kopo.poly.handler;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorMsg {

    ERR100("Do Not Login"),

    ERR300("Token Error"),

    ERR310("TOKEN ERROR"),

    ERR320("NOT VALID REFRESH TOKEN"),

    ERR330("NOT VALID TOKEN"),

    ERR400("ACCESS TOKEN EMPTY"),

    ERR410("ACCESS TOKEN EXPIRED"),

    ERR500("REFRESH TOKEN EMPTY"),

    ERR510("REFRESH TOKEN EXPIRED"),

    ERR600("AUTH ERROR[ACCESSDENIEDEXCEPTION]");

    private final String value;
}
