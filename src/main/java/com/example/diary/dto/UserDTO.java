package com.example.diary.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.Column;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;

public class UserDTO {

    @NotBlank
    private String firstname;

    @NotBlank
    private String lastname;

    @NotBlank
    private String email;

    @NotBlank
    private String name;

    @NotNull
    private LocalDate birth;

    @NotBlank
    private String password;

    public UserDTO(String firstname, String lastname, String email, String name, LocalDate birth, String password) {
        this.firstname = firstname;
        this.lastname = lastname;
        this.email = email;
        this.name = name;
        this.birth = birth;
        this.password = password;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public LocalDate getBirth() {
        return birth;
    }

    public void setBirth(LocalDate birth) {
        this.birth = birth;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
