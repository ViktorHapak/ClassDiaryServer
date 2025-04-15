package com.example.diary.models;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

import java.util.Objects;

@Entity
@Table(name="finalgrades")
public class FinalGrades {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "subjectname")
    private String subjectName;

    @Column(name = "grade1")
    private Integer grade1;

    @Column(name = "grade2")
    private Integer grade2;

    @Column(name = "exam")
    private Integer exam;

    @Column(name = "grade")
    private Integer grade;

    @ManyToOne(fetch = FetchType.LAZY)
    @JsonIgnore
    @JoinColumn(name="student_id", referencedColumnName = "id")
    private Student student;

    public FinalGrades() {
    }

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public Integer getGrade1() {
        return grade1;
    }

    public void setGrade1(Integer grade1) {
        this.grade1 = grade1;
    }

    public Integer getGrade2() {
        return grade2;
    }

    public void setGrade2(Integer grade2) {
        this.grade2 = grade2;
    }

    public Integer getExam() {
        return exam;
    }

    public void setExam(Integer exam) {
        this.exam = exam;
    }

    public Integer getGrade() {
        return grade;
    }

    public void setGrade(Integer grade) {
        this.grade = grade;
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
        FinalGrades that = (FinalGrades) o;
        return Objects.equals(student, that.student);
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
