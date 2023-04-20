package com.eroom.oauth2sample.service;

import com.eroom.oauth2sample.domain.Member;
import com.eroom.oauth2sample.domain.MemberRepository;
import com.eroom.oauth2sample.dto.Role;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final MemberRepository memberRepository;

    private final HttpSession httpSession;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 서비스 구분을 위한 작업 (구글:google, 네이버: naver)
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        String email;
        Map<String, Object> response = oAuth2User.getAttributes();

        switch (registrationId) {
            case "naver":
                Map<String, Object> hash = (Map<String, Object>) response.get("response");
                email = (String) hash.get("email");
                break;
            case "google":
                email = (String) response.get("email");
                break;
            default:
                throw new OAuth2AuthenticationException("허용되지 않는 인증입니다.");
        }

        // 이미 가입한 사람인지 확인
        Member member;
        Optional<Member> optionalUser = memberRepository.findByEmail(email);

        if (optionalUser.isPresent()) { // 이미 있는 사람이면
            member = optionalUser.get();
        } else { // 가입한적 없는 사람이면
            member = new Member();
            member.setEmail(email);
            member.setRole(Role.ROLE_USER);
            memberRepository.save(member);
        }

        httpSession.setAttribute("member", member);


        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(member.getRole().toString())),
                oAuth2User.getAttributes(),
                userNameAttributeName
        );
    }
}
