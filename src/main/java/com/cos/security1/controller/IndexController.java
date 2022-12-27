package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@GetMapping({"","/"})
	public String index() {
		// 찾는 폴더 => src/main/resources/
		// templates(prefix), .mustache(suffix) 
		return "index"; // src/main/resources/templates/index.mustache 를 찾는다.
	}
	
	@GetMapping("/user")
	public @ResponseBody String user() {
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	// 스프링시큐리티에서 잡는다.
	// => SecurityConfig 설정하면 잡지 않음
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		System.out.println(user);
		// 회원가입은 잘 되지만 (비밀번호 1234)
		// 시큐리티로 로그인할 수 없음 -> 패스워드 암호화가 안됨
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		// 따라서 비밀번호 암호화
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		userRepository.save(user);
		return "redirect:/loginForm";
	}
	
	
	// 간단하게 메소드 하나에 걸고 싶을 때 Secured나 PreAuthorize, PostAuthorize를 걸고
	// 아니면 Config에 설정한다.
	
	@Secured("ROLE_ADMIN") // 해당권한을 가졌을 경우만 들어가짐
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}
	
	// 여러개 걸고 싶으면 아래꺼 쓰자
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // data 메소드가 실행되기 직전에 실행됨
	//@PostAuthorize("") // 함수가 끝나고 난 뒤에 수행
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터정보";
	}

}
