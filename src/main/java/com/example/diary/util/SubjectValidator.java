package com.example.diary.util;

import com.example.diary.models.Subject;
import com.example.diary.repositories.StudentRepository;
import com.example.diary.repositories.SubjectRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class SubjectValidator implements Validator {

    @Autowired
    private SubjectRepository subjectRepository;

    @Override
    public boolean supports(Class<?> clazz) {
        return Subject.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        Subject subject = (Subject) target;

        if(subjectRepository.findByName(subject.getName()).isPresent())
            errors.rejectValue("name", "", "This subject is already exist!");

    }
}
