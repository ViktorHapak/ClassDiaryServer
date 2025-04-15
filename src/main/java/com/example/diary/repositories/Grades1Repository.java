package com.example.diary.repositories;

import com.example.diary.models.Grades1;
import com.example.diary.models.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface Grades1Repository extends JpaRepository<Grades1, Integer> {

    Optional<Grades1> findByStudentAndSubjectName(Student student, String subjectName);

    List<Grades1> findByStudent(Student student);

    List<Grades1> findBySubjectName(String name);
}
