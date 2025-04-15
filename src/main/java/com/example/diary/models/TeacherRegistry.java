package com.example.diary.models;

import com.fasterxml.jackson.annotation.JsonGetter;
import jakarta.persistence.*;

import java.util.Objects;

@Entity
@Table(name = "teacherregistry")
public class TeacherRegistry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Integer id;

    @ManyToOne
    @JoinColumn(name="teacher_id", referencedColumnName = "id")
    private User teacher;

    @ManyToOne
    @JoinColumn(name="subject_id", referencedColumnName = "id")
    private Subject subject;

    @ManyToOne
    @JoinColumn(name="class_id", referencedColumnName = "id")
    private Sclass sclass;

    public TeacherRegistry() {
    }

    public TeacherRegistry(User teacher, Subject subject, Sclass sclass) {
    }

    public User getTeacher() {
        return teacher;
    }

    public void setTeacher(User teacher) {
        this.teacher = teacher;
    }

    public Subject getSubject() {
        return subject;
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    public Sclass getSclass() {
        return sclass;
    }

    public void setSclass(Sclass sclass) {
        this.sclass = sclass;
    }

    @JsonGetter("id")
    public Integer getJsonId() {
        return id;
    }

    @JsonGetter("teacher")
    public String getJsonTeacher() {
        return teacher.toString();
    }

    @JsonGetter("subject")
    public String getJsonSubject() {
        return subject.toString();
    }

    @JsonGetter("sclass")
    public String getJsonSclass() {
        return sclass.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TeacherRegistry that = (TeacherRegistry) o;
        return Objects.equals(subject, that.subject) && Objects.equals(sclass, that.sclass);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, sclass);
    }

    @Override
    public String toString() {
        return teacher + "-" + subject + "-" + sclass;
    }
}
