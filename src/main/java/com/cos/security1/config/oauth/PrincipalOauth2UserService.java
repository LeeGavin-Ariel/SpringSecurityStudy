package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.config.CustomBCryptPasswordEncoder;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService{

	@Autowired
	private CustomBCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserRepository userRepository;
	
	// 후처리 되는 함수
	// 구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
	// 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다. --> 중요!
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("getClientRegistration:"+userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인했는지 확인가능
		System.out.println("getAccessToken:"+userRequest.getAccessToken().getTokenValue());

		OAuth2User oauth2User = super.loadUser(userRequest);
		// 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인 -> Code 리턴(OAuth-Client 라이브러리) -> AccessToken요청
		// userRequest 정보 -> 구글로부터 회원 프로필 받아줌(이때 사용 되는 것이 loadUser 함수) -> 회원프로필
		System.out.println("getAttributes:"+super.loadUser(userRequest).getAttributes());
		
		String provider = userRequest.getClientRegistration().getClientId(); // google
		String providerId = oauth2User.getAttribute("sub");
		String username = provider+"_"+providerId; // google_1~~
		String email = oauth2User.getAttribute("email");
		String password = bCryptPasswordEncoder.encode("겟인데어");
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUserName(username);
		
		if(userEntity == null) {
			userEntity = User.builder()
					.userName(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		}
		
		// 회원가입 강제 진행 예정
		//return super.loadUser(userRequest);
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}

	// username = google_(sub)
	// password = 암호화(겟인데어) -- null만 아니면 됨
	// email = 이메일
	// role = ROLE_USER
	// provider = google
	// providerId = sub
}