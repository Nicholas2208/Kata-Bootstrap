package ru.kata.springboot_security.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.kata.springboot_security.demo.model.Role;
import ru.kata.springboot_security.demo.model.User;
import ru.kata.springboot_security.demo.service.RoleService;
import ru.kata.springboot_security.demo.service.UserService;
import ru.kata.springboot_security.demo.service.UserValidationService;

import java.util.List;
import java.util.Set;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private UserService userService;
    private RoleService roleService;
    private UserValidationService validationService;

    public AdminController(UserService userService,
                           RoleService roleService,
                           UserValidationService validationService) {
        this.userService = userService;
        this.roleService = roleService;
        this.validationService = validationService;
    }

    @GetMapping("/")
    public String getAllUsers(Model model) {
        List<User> allUsers = userService.getAll();
        Set<Role> roles = roleService.getAllRoles();
        User form = new User();

        model.addAttribute("allUsers", allUsers);
        model.addAttribute("appUserForm", form);
        model.addAttribute("roles", roles);

        return "list_users";
    }

    @PostMapping("/save")
    public String save(Model model,
                       @ModelAttribute("appUserForm") @Validated User user,
                       BindingResult result) {
        String err = validationService.validateUser(user);
        if (!err.isEmpty()) {
            ObjectError error = new ObjectError("globalError", err);
            result.addError(error);
        }

        if (result.hasErrors()) {
            Set<Role> roles = roleService.getAllRoles();
            model.addAttribute("roles", roles);
            List<User> allUsers = userService.getAll();
            model.addAttribute("allUsers", allUsers);

            return "list_users";
        }

        userService.save(user);
        return "redirect:/admin/";
    }

    @PostMapping("update/{id}")
    public String updateUser(@ModelAttribute("user") User user,
                             @PathVariable("id") Long id) {
        userService.update(id,user);
        return "redirect:/admin/";
    }

    @PostMapping("/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userService.delete(id);
        return "redirect:/admin/";
    }
}
