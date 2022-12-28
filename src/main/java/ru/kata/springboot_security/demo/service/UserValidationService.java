package ru.kata.springboot_security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.kata.springboot_security.demo.model.User;

import java.util.Optional;

@Service
public class UserValidationService {
    private UserService userService;

    public UserValidationService(UserService userService) {
        this.userService = userService;
    }

    public String validateUser(User user) {
        String message = "";

        Optional<User> dbUser = userService.findByEmail(user.getEmail());
        if (!dbUser.isEmpty()) {
            message = "User with email " + user.getEmail() + " is already registered!";
        }

        return message;
    }
}
