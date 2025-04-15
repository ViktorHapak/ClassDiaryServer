package com.example.diary.util;

import com.example.diary.models.TeacherRegistry;
import com.example.diary.repositories.TeacherRegistryRepository;
import jakarta.persistence.Column;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Valid;

import jakarta.validation.executable.ExecutableValidator;
import jakarta.validation.metadata.BeanDescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.util.Set;

@Component
public class TeacherRegistryValidator implements Validator {

    @Autowired
    private TeacherRegistryRepository teacherRegistryRepository;

    @Override
    public boolean supports(Class<?> clazz) {
        return TeacherRegistry.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        TeacherRegistry teacherRegistry = (TeacherRegistry) target;

        if(teacherRegistryRepository.findBySubjectAndSclassAndTeacher(teacherRegistry.getSubject(),
                teacherRegistry.getSclass(), teacherRegistry.getTeacher()).isPresent())
            errors.rejectValue("teacher", "", "A tanár már tanítja a tárgyat az osztálynak");

        if(teacherRegistryRepository.findBySubjectAndSclass(teacherRegistry.getSubject(),
                teacherRegistry.getSclass()).isPresent()) errors.rejectValue("sclass", "", "Az osztálynak már van ilyen tantárgya");
    }
}
