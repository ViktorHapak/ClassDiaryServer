package com.example.diary.repositories;

import com.example.diary.models.Grades1;
import com.example.diary.models.Grades2;
import com.example.diary.models.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface Grades2Repository extends JpaRepository<Grades2, Integer> {

    Optional<Grades2> findByStudentAndSubjectName(Student student, String subjectName);

    List<Grades2> findByStudent(Student student);


    List<Grades2> findBySubjectName(String name);
}
