package com.example.demo.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.example.demo.dao.Permession;

@Repository
@Transactional
public interface IPermessionRepository extends JpaRepository<Permession, Integer>{

	List<Permession> findById(int id);

	Permession findByRole(String role);
		
}
