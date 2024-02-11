package Jung.jwt.dto;

import lombok.Data;

/**
 * token 정보를 response
 */
@Data
public class TokenDto {

    private String token;

    public TokenDto(String token) {
        this.token = token;
    }
}
