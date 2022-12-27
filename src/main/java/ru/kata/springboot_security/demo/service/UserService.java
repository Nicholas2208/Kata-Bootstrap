package ru.kata.springboot_security.demo.service;

import ru.kata.springboot_security.demo.model.User;

import java.util.List;
import java.util.Optional;

public interface UserService {
    Optional<User> findByEmail(String email);
    void save(User user);
    List<User> getAll();
    User getUser(Long id);
    void update(long id, User user);
    void delete(Long id);
}
