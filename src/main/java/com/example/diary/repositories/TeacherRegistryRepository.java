package com.example.diary.repositories;

import com.example.diary.models.*;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TeacherRegistryRepository extends JpaRepository<TeacherRegistry, Integer> {


    List<TeacherRegistry> findByTeacher(User user);

    List<TeacherRegistry> findBySclass(Sclass sclass);

    List<TeacherRegistry> findBySubject(Subject subject);

    Optional<TeacherRegistry> findBySubjectAndSclassAndTeacher(Subject subject,
                                                               Sclass sclass,
                                                               User teacher);
    Optional<TeacherRegistry> findBySubjectAndSclass(Subject subject, Sclass sclass);

    Page<TeacherRegistry> findAll(Pageable pageable);

    Page<TeacherRegistry> findByTeacher(User user, Pageable pageable);

    Page<TeacherRegistry> findBySclass(Sclass sclass, Pageable pageable);

    Page<TeacherRegistry> findBySubject(Subject subject, Pageable pageable);
}
