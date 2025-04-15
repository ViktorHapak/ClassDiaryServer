package com.example.diary.repositories;

import com.example.diary.models.Sclass;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SclassRepository extends JpaRepository<Sclass, Integer> {

    List<Sclass> findAllBy();

    List<Sclass> findByYear(int year);

    Optional<Sclass> findByName(String classname);


}
