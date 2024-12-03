package cn.wildfirechat.app.shiro;

import cn.wildfirechat.app.jpa.UserPassword;
import cn.wildfirechat.app.jpa.UserPasswordRepository;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class Md5CredentialsMatcher implements CredentialsMatcher {
    private final UserPasswordRepository userPasswordRepository;
    @Lazy
    public Md5CredentialsMatcher(UserPasswordRepository userPasswordRepository) {
        this.userPasswordRepository = userPasswordRepository;
    }
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken ut = (UsernamePasswordToken)token;
            String userId = ut.getUsername();
            String password = new String(ut.getPassword());
            Optional<UserPassword> optional = userPasswordRepository.findById(userId);
            String salt = null;
            if (optional.isPresent()) {
                UserPassword up = optional.get();
                salt = up.getSalt();
            }

            if (salt != null) {
                return DigestUtils.md5Hex(password+salt).equals(info.getCredentials());
            } else {
                return DigestUtils.md5Hex(password).equals(info.getCredentials());
            }
        }
        return false;
    }
}
