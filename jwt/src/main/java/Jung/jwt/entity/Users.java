package Jung.jwt.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(length = 50, unique = true)
    private String username;

    @Column(length = 100)
    private String password;

    @Column(length = 50)
    private String nickname;

    private boolean activated;

    @ManyToMany
    @JoinTable(
            name = "user_authority",  //중간 테이블 생성
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "authority_name"))
    private Set<Authority> authorities;
}
