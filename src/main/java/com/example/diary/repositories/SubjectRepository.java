package com.example.diary.repositories;

import com.example.diary.models.Subject;
import com.example.diary.models.User;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SubjectRepository  extends JpaRepository<Subject,Integer> {

    Optional<Subject> findById(Integer id);

    Optional<Subject> findByName(String name);

    Page<Subject> findAll(Pageable pageable);

    Page<Subject> findByNameStartingWith(@NotBlank String name, Pageable pageable);
}
