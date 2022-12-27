package ru.kata.springboot_security.demo.service;

import ru.kata.springboot_security.demo.model.Role;

import java.util.Set;

public interface RoleService {
    Set<Role> getAllRoles();
    Role getRoleByName(String name);
}
