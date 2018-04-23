package com.example.demo.repository;

import java.util.List;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.dao.User;

@Repository
@Transactional
public interface IUserRepository extends JpaRepository<User, Integer>{

	User findByUserName(String userName);
	
}
