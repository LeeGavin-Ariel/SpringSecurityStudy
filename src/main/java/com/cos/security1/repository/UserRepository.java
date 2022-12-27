package com.cos.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.User;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository라는 어노테이션이 없어도 IoC 됨 --> JpaRepository를 상속했으므로
public interface UserRepository extends JpaRepository<User, Integer>{
	// findBy 규칙 -> UserName
	public User findByUserName(String userName);
}
