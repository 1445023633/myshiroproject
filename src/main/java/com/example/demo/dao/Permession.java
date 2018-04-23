package com.example.demo.dao;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="T_PERMESSION")
public class Permession {
	@Id
	@GeneratedValue
	private int id;
	
	@Column(name="ROLE")
	private String role;
	
	@Column(name="PERMISSIONS")
	private String permissions;
	
	@Column(name="DESCRIPTIONS")
	private String descriptions;
	
	public Permession(int id, String role, String permissions, String descriptions) {
		super();
		this.id = id;
		this.role = role;
		this.permissions = permissions;
		this.descriptions = descriptions;
	}
	public Permession() {
		super();
	}
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	public String getPermissions() {
		return permissions;
	}
	public void setPermissions(String permissions) {
		this.permissions = permissions;
	}
	public String getDescriptions() {
		return descriptions;
	}
	public void setDescriptions(String descriptions) {
		this.descriptions = descriptions;
	}
}
