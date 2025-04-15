package com.example.diary.models;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

import java.util.Objects;

@Entity
@Table(name="grades2")
public class Grades2 {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "subjectname")
    private String subjectName;

    @Column(name = "modulgrades1")
    private String modulegrades1;

    @Column(name = "module1")
    private Integer module1;

    @Column(name = "modulgrades2")
    private String modulegrades2;

    @Column(name = "module2")
    private Integer module2;

    @Column(name = "modulgrades3")
    private String modulegrades3;

    @Column(name = "module3")
    private Integer module3;

    @Column(name = "semester")
    private Integer semester;

    @ManyToOne(fetch = FetchType.LAZY)
    @JsonIgnore
    @JoinColumn(name="student_id", referencedColumnName = "id")
    private Student student;

    public Grades2() {
    }

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public String getModulegrades1() {
        return modulegrades1;
    }

    public void setModulegrades1(String modulegrades1) {
        this.modulegrades1 = modulegrades1;
    }

    public Integer getModule1() {
        return module1;
    }

    public void setModule1(Integer module1) {
        this.module1 = module1;
    }

    public String getModulegrades2() {
        return modulegrades2;
    }

    public void setModulegrades2(String modulegrades2) {
        this.modulegrades2 = modulegrades2;
    }

    public Integer getModule2() {
        return module2;
    }

    public void setModule2(Integer module2) {
        this.module2 = module2;
    }

    public String getModulegrades3() {
        return modulegrades3;
    }

    public void setModulegrades3(String modulegrades3) {
        this.modulegrades3 = modulegrades3;
    }

    public Integer getModule3() {
        return module3;
    }

    public void setModule3(Integer module3) {
        this.module3 = module3;
    }

    public Integer getSemester() {
        return semester;
    }

    public void setSemester(Integer semester) {
        this.semester = semester;
    }

    public Student getStudent() {
        return student;
    }

    public void setStudent(Student student) {
        this.student = student;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        Grades2 grades2 = (Grades2) o;
        return Objects.equals(student, grades2.student);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(student);
    }

    // Getter for student ID
    @JsonGetter("studentId")
    public Integer getStudentId() {
        return student != null ? student.getId() : null;
    }

    // Getter for student Name
    @JsonGetter("studentName")
    public String getStudentName() {
        return student != null ? student.getName() : null;
    }
}
