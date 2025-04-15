package com.example.diary.repositories;

import com.example.diary.models.FinalGrades;
import com.example.diary.models.Grades1;
import com.example.diary.models.Grades2;
import com.example.diary.models.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FinalGradesRepository extends JpaRepository<FinalGrades, Integer> {

    Optional<FinalGrades> findByStudentAndSubjectName(Student student, String subjectName);

    List<FinalGrades> findByStudent(Student student);

    List<FinalGrades> findBySubjectName(String name);
}
