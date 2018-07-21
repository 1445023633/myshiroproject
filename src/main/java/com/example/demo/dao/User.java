package com.example.demo.dao;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="T_USER")
public class User {
	@Id
	@GeneratedValue
	private int id;
			
	@Column(name="USER_NAME")
	private String userName;
	
	@Column(name="PASS_WORD")
	private String password;
	
	@Column(name="ROLES")
	private String roles;
	
	@Column(name="DESCRIPTIONS")
	private String descriptions;
	
	public User(int id, String userName, String password, String roles, String descriptions) {
		super();
		this.id = id;
		this.userName = userName;
		this.password = password;
		this.roles = roles;
		this.descriptions = descriptions;
	}
	public User() {
		super();
	}
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getRoles() {
		return roles;
	}
	public void setRoles(String roles) {
		this.roles = roles;
	}
	public String getDescriptions() {
		return descriptions;
	}
	public void setDescriptions(String descriptions) {
		this.descriptions = descriptions;
	}


}
	