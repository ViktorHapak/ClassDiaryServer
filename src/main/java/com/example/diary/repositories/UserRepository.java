package com.example.diary.repositories;

import com.example.diary.models.Role;
import com.example.diary.models.Sclass;
import com.example.diary.models.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findById(Integer id);

    Optional<User> findByName(String name);

    Optional<User> findByEmail(String email);

    Optional<User> findBySclass(Sclass sclass);

    List<User> findByNameStartingWith(String name);

    List<User> findByUserrole(Role role);

    Page<User> findByNameStartingWith(String name, Pageable pageable);

    Page<User> findByUserroleAndNameStartingWith(Role role, String name, Pageable pageable);

    Boolean existsByName(String name);

    Boolean existsByEmail(String email);


}
