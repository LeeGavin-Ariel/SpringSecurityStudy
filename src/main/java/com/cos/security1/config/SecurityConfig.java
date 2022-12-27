package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// secured 어노테이션 활성화, preAuthorize & postAuthorize 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
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
			.defaultSuccessUrl("/"); // loginForm을 통해서 로그인을 하면 내가 가려고 하는 페이지로 이동시켜줌
			// 만약 /user에서 로그인을 했으면 /user로 보내줌
	}
}
