package com.example.diary.util;

import com.example.diary.models.Student;
import com.example.diary.repositories.StudentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.annotation.Validated;

import java.lang.annotation.Annotation;
import java.util.Optional;

@Component
public class StudentValidator implements Validator {

    @Autowired
    private StudentRepository studentRepository;



    @Override
    public boolean supports(Class<?> clazz) {
        return Student.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        Student student = (Student) target;

        Optional<Student> existingStudent = studentRepository.findByName(student.getName());

        if (existingStudent.isPresent()) {
            if (student.getId() == null) {
                // Reject immediately for new students with duplicate names
                errors.rejectValue("name", "", "A tanuló már létezik!");
            } else if (!existingStudent.get().getId().equals(student.getId())) {
                // Prevent updates from using another student's name
                errors.rejectValue("name", "", "Már létezik ilyen nevű tanuló!");
            }
        }

    }
}
