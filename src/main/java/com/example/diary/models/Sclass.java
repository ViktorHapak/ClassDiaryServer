package com.example.diary.models;


import com.fasterxml.jackson.annotation.JsonGetter;
import jakarta.persistence.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name="class")
public class Sclass {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "year")
    private int year;

    @Column(name = "marking")
    private char marking;

    @Column(name = "name")
    private String name;


    @OneToOne()
    @JoinColumn(name="teacher_id", referencedColumnName = "id")
    private User teacher;

    @OneToMany(mappedBy = "sclass", fetch = FetchType.LAZY)
    private List<TeacherRegistry> teacherRegistries;

    @OneToMany(mappedBy = "sclass", fetch = FetchType.LAZY)
    private List<Student> students;

    public Sclass(int year, char marking, String name) {
        this.year = year;
        this.marking = marking;
        this.name = name;
    }

    public Sclass() {

    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public int getYear() {
        return year;
    }

    public void setYear(int year) {
        this.year = year;
    }

    public char getMarking() {
        return marking;
    }

    public void setMarking(char marking) {
        this.marking = marking;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public User getClassteacher() {
        return teacher;
    }

    public void setClassteacher(User classteacher) {
        this.teacher = classteacher;
    }

    public List<TeacherRegistry> getTeacherRegistries() {
        return teacherRegistries;
    }

    public void setTeacherRegistries(List<TeacherRegistry> teacherRegistries) {
        this.teacherRegistries = teacherRegistries;
    }

    public List<Student> getStudents() {
        return students;
    }

    public void setStudents(List<Student> students) {
        this.students = students;
    }

    @JsonGetter("teacher")
    public String getJsonTeacher(){
        try{return teacher.getName();}
        catch (NullPointerException e){ return "";}
    }

    @JsonGetter("teacherRegistries")
    public List<String> getJsonTeacherRegistries(){
        return teacherRegistries.stream().map(e -> e.toString()).collect(Collectors.toList());
    }

    @JsonGetter("students")
    public List<String> getJsonStudents(){
        return students.stream().map(e->e.getName()).collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return name;
    }


}
