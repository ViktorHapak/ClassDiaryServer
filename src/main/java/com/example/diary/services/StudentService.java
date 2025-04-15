package com.example.diary.services;

import com.example.diary.models.*;
import com.example.diary.repositories.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class StudentService {

    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private TeacherRegistryRepository teacherRegistryRepository;

    @Autowired
    private SclassRepository sclassRepository;

    @Autowired
    private Grades1Repository grades1Repository;

    @Autowired
    private Grades2Repository grades2Repository;

    @Autowired
    private FinalGradesRepository finalGradesRepository;

    @Transactional
    public void save(Student student){
        studentRepository.save(student);
    }

    public Student find(Integer id){
        return studentRepository.findById(id).orElseThrow(RuntimeException::new);
    }

    public Student findStudentByName(String name){
        return studentRepository.findByName(name).orElseThrow(RuntimeException::new);
    }


    public List<Student> findAll(){
        return studentRepository.findAll();
    }

    public Page<Student> findAllPage(Pageable pageable){
        return studentRepository.findAll(pageable);
    }

    public List<Student> findByClass(String classname){
        Sclass sclass = sclassRepository.findByName(classname).orElseThrow(RuntimeException::new);
        return studentRepository.findBySclass(sclass);
    }

    public Page<Student> findByClassAndNamePage(String classname, String name, Pageable pageable){
        Sclass sclass = sclassRepository.findByName(classname).orElseThrow(RuntimeException::new);
        return studentRepository.findBySclassAndNameStartingWith(sclass,name,pageable);
    }

    public Page<Student> findIfNoClassPage(Pageable pageable){
        return studentRepository.findBySclass(null,pageable);
    }

    public Page<Student> findIfNoClassByNamePage(String name, Pageable pageable){
        return studentRepository.findBySclassAndNameStartingWith(null,name,pageable);
    }

    public Page<Student> findByClassPage(String classname, Pageable pageable){
        Sclass sclass = sclassRepository.findByName(classname).orElseThrow(RuntimeException::new);
        return studentRepository.findBySclass(sclass,pageable);
    }

    public List<Student> findName(String name){
        return studentRepository.findByNameStartingWith(name);
    }


    public Page<Student> findByNamePage(String name, Pageable pageable){
        return studentRepository.findByNameStartingWith(name, pageable);
    }

    public int count(){
        return (int) studentRepository.count();
    }

    public int countClass(String classname){
        Sclass sclass = sclassRepository.findByName(classname).orElseThrow(RuntimeException::new);
        return (int) studentRepository.findBySclass(sclass).stream().count();
    }


    @Transactional
    public void update(Integer id, Student student){
        Optional<Student> studentToUpdate =
                Optional.ofNullable(studentRepository.findById(id).orElseThrow(RuntimeException::new));

        if(studentToUpdate.isPresent()){
            Student _student = studentToUpdate.get();
            _student.setAddress(student.getAddress());
            _student.setBirth(student.getBirth());
            _student.setName(student.getName());
            studentRepository.save(student);
        }
    }

    @Transactional
    public void delete(Student student){
        grades1Repository.deleteAll(grades1Repository.findByStudent(student));
        grades2Repository.deleteAll(grades2Repository.findByStudent(student));
        finalGradesRepository.deleteAll(finalGradesRepository.findByStudent(student));
        studentRepository.delete(student);
    }

    @Transactional
    public void deleteAll(){
        grades1Repository.deleteAll();
        grades2Repository.deleteAll();
        finalGradesRepository.deleteAll();

        studentRepository.deleteAll();
    }

    @Transactional
    public void deleteAllFromClass(Sclass sclass){
        studentRepository.deleteAll(studentRepository.findBySclass(sclass));
    }


    //Ha eltávolítanánk az osztályból, minden jegybejegyzését is el kell távolítanunk:
    @Transactional
    public void deleteFromClass(Student student){
        /*grades1Repository.deleteAll(grades1Repository.findByStudent(student));
        grades2Repository.deleteAll(grades2Repository.findByStudent(student));
        finalGradesRepository.deleteAll(finalGradesRepository.findByStudent(student));*/

        if(student.getClass() == null) throw new RuntimeException();
        student.setSclass(null);
        studentRepository.save(student);
    }

    /*Külön függvénnyel hozzáadjuk az osztályhoz, ekkor az osztály minden tantárgyához lesz neki grade-bejegyzése.
    Ellenőrizzük, nincs -e már grade-bejegyzése az adott tárgyhoz! */
    @Transactional
    public void addToClass(Student student, Sclass sclass){
        if (student.getSclass()!=null){
            /*grades1Repository.deleteAll(grades1Repository.findByStudent(student));
            grades2Repository.deleteAll(grades2Repository.findByStudent(student));
            finalGradesRepository.deleteAll(finalGradesRepository.findByStudent(student));*/
            student.setSclass(null);
        }

        List<TeacherRegistry> registries = teacherRegistryRepository.findBySclass(sclass);
        List<Subject> subjects = registries.stream().map(el -> el.getSubject()).distinct().collect(Collectors.toList());


        for (Subject subject : subjects){
            if(grades1Repository.findByStudentAndSubjectName(student,subject.getName()).isEmpty()){
            Grades1 grades1 = new Grades1();
            grades1.setSubjectName(subject.getName());
            student.getGrades1List().add(grades1);
            grades1.setStudent(student);
            grades1Repository.save(grades1);}

            if(grades2Repository.findByStudentAndSubjectName(student,subject.getName()).isEmpty()){
            Grades2 grades2 = new Grades2();
            grades2.setSubjectName(subject.getName());
            student.getGrades2List().add(grades2);
            grades2.setStudent(student);
            grades2Repository.save(grades2);}

            if(finalGradesRepository.findByStudentAndSubjectName(student,subject.getName()).isEmpty()){
            FinalGrades finalGrades = new FinalGrades();
            finalGrades.setSubjectName(subject.getName());
            student.getFinalgradesList().add(finalGrades);
            finalGrades.setStudent(student);
            finalGradesRepository.save(finalGrades);}

        }

        sclass.getStudents().add(student);
        student.setSclass(sclass);
    }


}
