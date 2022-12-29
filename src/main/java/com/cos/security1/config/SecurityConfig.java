package com.cos.security1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;



@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// secured 어노테이션 활성화, preAuthorize & postAuthorize 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	
	@Autowired
	private PrincipalOauth2UserService principalOauth2UserService;
	
	// 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers("/user/**").authenticated()
			.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // 해당 권한을 가진 것만 허용
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll() // 위의 세개를 제외하고는 허용
			.and()
			.formLogin() // 사용자 설정 로그인페이지
			.loginPage("/loginForm")
			.usernameParameter("userName")
			.loginProcessingUrl("/login") // /login이라는 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
			.defaultSuccessUrl("/") // loginForm을 통해서 로그인을 하면 내가 가려고 하는 페이지로 이동시켜줌
			// 만약 /user에서 로그인을 했으면 /user로 보내줌
			.and()
			.oauth2Login()
			.loginPage("/loginForm") // 해당 페이지에서 oauth 로그인을 진행하겠다.
			// 구글 로그인이 된 뒤의 후처리
			//1. 코드받기(인증)
			//2. 엑세스토큰(사용자 정보에 접근할 권한이 생김)
			//3. 사용자 프로필 정보를 가져옴
			//4-1. 정보를 토대로 회원가입을 자동으로 진행시키기도 함
			//4-2. 정보가 모자랄 경우 추가 정보 기입 
			.userInfoEndpoint()
			//Tip! 구글 로그인이 완료가 되면 코드를 받는 것이 아니라, 엑세스토큰+사용자 프로필정보를 한방에 받는다.
			.userService(principalOauth2UserService);
	}
}
