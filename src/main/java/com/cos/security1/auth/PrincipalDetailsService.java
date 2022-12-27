package com.cos.security1.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

// 시큐리티 설정에서 loginProcessingUrl("/login")
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어있는
// loadUserByUsername 함수가 실행 -> 이건 규칙
@Service
public class PrincipalDetailsService implements UserDetailsService{

	@Autowired
	private UserRepository userRepository;
	
	// 시큐리티 Session(내부 Authentication(내부 UserDetails))
	// Session안에 자동으로 만들어지면서 들어간다.
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUserName(username);
		if(userEntity != null) {
			return new PrincipalDetails(userEntity);
		}
		return null;
	}

}
