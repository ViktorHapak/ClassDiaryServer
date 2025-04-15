package com.example.diary.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonGetter;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name = "user", uniqueConstraints = {
        @UniqueConstraint(columnNames = "email"),
        @UniqueConstraint(columnNames = "name")})

public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @NotBlank
    @Column(name = "firstname")
    private String firstname;

    @NotBlank
    @Column(name = "lastname")
    private String lastname;

    @NotBlank
    @Column(name = "email")
    private String email;

    @NotBlank
    @Column(name = "name")
    private String name;

    @NotNull
    @Column(name= "birth")
    private LocalDate birth;


    @Column(name = "password")
    private String password;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name="role")
    private Role userrole;

    @OneToOne(mappedBy = "teacher")
    private Sclass sclass;

    @OneToMany(mappedBy = "teacher", fetch = FetchType.LAZY)
    private List<TeacherRegistry> teacherRegistries;

    @ManyToMany(mappedBy = "parents")
    private List<Student> children;

    public User() {
    }

    public User(String firstname, String lastname,
                String email, String name, LocalDate birth,
                String password) {
        this.firstname = firstname;
        this.lastname = lastname;
        this.email = email;
        this.name = name;
        this.birth = birth;
        this.password = password;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public LocalDate getBirth() {
        return birth;
    }

    public void setBirth(LocalDate birth) {
        this.birth = birth;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public Role getUserrole() {
        return userrole;
    }

    public void setUserrole(Role userrole) {
        this.userrole = userrole;
    }

    public Sclass getSclass() {
        return sclass;
    }

    public void setSclass(Sclass sclass) {
        this.sclass = sclass;
    }

    public List<TeacherRegistry> getTeacherRegistries() {
        return teacherRegistries;
    }

    public void setTeacherRegistries(List<TeacherRegistry> teacherRegistries) {
        this.teacherRegistries = teacherRegistries;
    }

    public List<Student> getChildren() {
        return children;
    }

    public void setChildren(List<Student> children) {
        this.children = children;
    }

    @JsonGetter("sclass")
    public String getJsonSclass(){
        try{return sclass.getName();}
        catch (NullPointerException e){ return "";}
    }

    @JsonGetter("teacherRegistries")
    public List<String> getJsonTeacherRegistries(){
        return teacherRegistries.stream().map(e -> e.toString()).collect(Collectors.toList());
    }

    @JsonGetter("children")
    public List<String> getJsonChildren(){
        return children.stream().map(e->e.getName()).collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return name;
    }

}
