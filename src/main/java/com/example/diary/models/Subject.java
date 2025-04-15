package com.example.diary.models;


import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "subject")
public class Subject {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @NotBlank
    @Column(name = "name")
    private String name;

    @OneToMany(mappedBy = "subject", fetch = FetchType.LAZY)
    @JsonIgnore
    private List<TeacherRegistry> teacherRegistries;

    public Subject() {
    }

    public Subject(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<TeacherRegistry> getTeacherRegistries() {
        return teacherRegistries;
    }

    public void setTeacherRegistries(List<TeacherRegistry> teacherRegistries) {
        this.teacherRegistries = teacherRegistries;
    }

    @JsonGetter("id")
    public Integer getId() {return id; }

    @Override
    public String toString() {
        return name;
    }
}
