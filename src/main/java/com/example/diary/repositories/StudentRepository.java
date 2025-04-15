package com.example.diary.repositories;

import com.example.diary.models.Sclass;
import com.example.diary.models.Student;
import com.example.diary.models.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface   StudentRepository  extends JpaRepository<Student, Integer>  {


    List<Student> findByNameStartingWith(String name);

    List<Student> findBySclass(Sclass sclass);

    Page<Student> findBySclass(Sclass sclass, Pageable pageable);

    Page<Student> findBySclassAndNameStartingWith(Sclass sclass, String name, Pageable pageable);


    Page<Student> findByNameStartingWith(String title, Pageable pageable);


    Optional<Student> findByName(String name);

    Boolean existsByName(String name);
}
