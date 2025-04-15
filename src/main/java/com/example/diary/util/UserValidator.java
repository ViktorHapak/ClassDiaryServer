package com.example.diary.util;


import com.example.diary.models.Student;
import com.example.diary.models.User;
import com.example.diary.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.Optional;

@Component
public class UserValidator implements Validator {

    @Autowired
    private UserRepository userRepository;


    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        User user = (User) target;

        Optional<User> existingUserByName = userRepository.findByName(user.getName());
        Optional<User> existingUserByEmail = userRepository.findByEmail(user.getEmail());

        // Validate username uniqueness
        if (existingUserByName.isPresent()) {
            if (user.getId() == null) {
                // New user, name must be unique
                errors.rejectValue("name", "error.username", "A felhasználónév foglalt!");
            } else if (!existingUserByName.get().getId().equals(user.getId())) {
                // Existing user, must not take another user's name
                errors.rejectValue("name", "error.username", "A felhasználónév foglalt!");
            }
        }

        // Validate email uniqueness
        if (existingUserByEmail.isPresent()) {
            if (user.getId() == null) {
                // New user, email must be unique
                errors.rejectValue("email", "error.email", "Az email foglalt!");
            } else if (!existingUserByEmail.get().getId().equals(user.getId())) {
                // Existing user, must not take another user's email
                errors.rejectValue("email", "error.email", "Az email foglalt!");
            }
        }


    }
}
