package com.example.diary.models;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name="student",uniqueConstraints =
        @UniqueConstraint(columnNames = "name"))
public class Student {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @NotBlank
    @Column(name = "name")
    private String name;

    @NotNull
    @Column(name = "birth")
    private LocalDate birth;

    @NotBlank
    @Column(name="address")
    private String address;

    @Column(name="info")
    private String info;


    @ManyToOne()
    @JoinColumn(name="class_id", referencedColumnName = "id")
    private Sclass sclass;

    @ManyToMany()
    @JoinTable(
            name="children_parent", joinColumns = @JoinColumn(name="child_id"),
            inverseJoinColumns = @JoinColumn(name = "parent_id"))
    private List<User> parents;

    @OneToMany(mappedBy = "student", fetch = FetchType.LAZY)
    @JsonIgnore
    private List<Grades1> grades1List;

    @OneToMany(mappedBy = "student", fetch = FetchType.LAZY)
    @JsonIgnore
    private List<Grades2> grades2List;

    @OneToMany(mappedBy = "student", fetch = FetchType.LAZY)
    @JsonIgnore
    private List<FinalGrades> finalgradesList;

    public Student(String name, LocalDate birth, String address) {
        this.name = name;
        this.birth = birth;
        this.address = address;
        this.info = "";
    }

    public Student(String name, LocalDate birth, String address, Sclass sclass) {
        this.name = name;
        this.birth = birth;
        this.address = address;
        this.sclass = sclass;
    }

    public Student() {

    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Sclass getSclass() {
        return sclass;
    }

    public void setSclass(Sclass sclass) {
        this.sclass = sclass;
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

    public void setBirth( LocalDate birth) {
        this.birth = birth;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public List<User> getParents() {
        return parents;
    }

    public void setParents(List<User> parents) {
        this.parents = parents;
    }

    public List<Grades1> getGrades1List() {
        return grades1List;
    }

    public void setGrades1List(List<Grades1> grades1List) {
        this.grades1List = grades1List;
    }

    public List<Grades2> getGrades2List() {
        return grades2List;
    }

    public void setGrades2List(List<Grades2> grades2List) {
        this.grades2List = grades2List;
    }

    public List<FinalGrades> getFinalgradesList() {
        return finalgradesList;
    }

    public void setFinalgrades1List(List<FinalGrades> finalgrades1List) {
        this.finalgradesList = finalgradesList;
    }

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    @JsonGetter("parents")
    public List<String> getJsonParents(){
        return parents.stream().map(e -> e.toString()).collect(Collectors.toList());
    }

    @JsonGetter("sclass")
    public String getJsonSclass(){
        try{return sclass.getName();}
        catch (NullPointerException e){ return "";}
    }

    /*@JsonGetter("grades1List")
    public List<String> getJsonGrades1List(){
        return grades1List.stream().map(e ->
                e.getSubjectName() + ": " + e.getSemester()).collect(Collectors.toList());
    }

    @JsonGetter("grades2List")
    public List<String> getJsonGrades2List(){
        return grades2List.stream().map(e ->
                e.getSubjectName() + ": " + e.getSemester()).collect(Collectors.toList());
    }

    @JsonGetter("finalgradesList")
    public List<String> getJsonFinalGradesList(){
        return finalgradesList.stream().map(e ->
                e.getSubjectName() + ": " + e.getGrade()).collect(Collectors.toList());
    }*/

    @Override
    public String toString() {
        return "Student{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", birth=" + birth +
                ", address='" + address + '\'' +
                ", info='" + info + '\'' +
                ", sclass=" + sclass +
                ", parents=" + parents +
                ", grades1List=" + grades1List +
                ", grades2List=" + grades2List +
                ", finalgradesList=" + finalgradesList +
                '}';
    }
}
