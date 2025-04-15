package com.example.diary.services;

import com.example.diary.models.*;
import com.example.diary.repositories.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class SubjectService {

    @Autowired
    private SubjectRepository subjectRepository;

    @Autowired
    private TeacherRegistryRepository teacherRegistryRepository;

    @Autowired
    private Grades1Repository grades1Repository;

    @Autowired
    private Grades2Repository grades2Repository;

    @Autowired
    private FinalGradesRepository finalGradesRepository;
    @Autowired
    private StudentRepository studentRepository;

    @Transactional
    public void save(Subject subject){
        subjectRepository.save(subject);
    }

    public Page<Subject> findAllSubjectByName(String name, Pageable pageable) {
        if(name.equals(" ")) return subjectRepository.findAll(pageable);
        else return subjectRepository.findByNameStartingWith(name,pageable);
    }

    public Page<Subject> findAllSubjectByNameAndClass(Sclass sclass, String name, Pageable pageable) {
        List<Subject> subjects = teacherRegistryRepository.findBySclass(sclass).stream()
                .map(e->e.getSubject()).filter(
                        e ->  e.getName().trim().toLowerCase().startsWith(name.trim().toLowerCase())
                ).collect(Collectors.toList());

        return new PageImpl<>(subjects, pageable, subjects.size());
    }

    public Subject find(Integer id) {
        return subjectRepository.findById(id).orElseThrow(RuntimeException::new);
    }

    public Subject findByName(String name) {
        return subjectRepository.findByName(name).orElseThrow(RuntimeException::new);
    }

    public Page<TeacherRegistry> findAllRegistry(Pageable pageable) {
        return teacherRegistryRepository.findAll(pageable);
    }

    public Page<TeacherRegistry> findRegistriesBySubject(Subject subject, Pageable pageable){
        return teacherRegistryRepository.findBySubject(subject,pageable);
    }

    public Page<TeacherRegistry> findRegistriesByTeacher(User user, Pageable pageable){
        return teacherRegistryRepository.findByTeacher(user,pageable);
    }

    public Page<TeacherRegistry> findRegistriesByClass(Sclass sclass, Pageable pageable){
        return teacherRegistryRepository.findBySclass(sclass,pageable);
    }

    public TeacherRegistry findRegistryById(Integer id){
        return teacherRegistryRepository.findById(id).orElseThrow(RuntimeException::new);
    }

    @Transactional
    public void delete(String subjectName) {
        Optional<Subject> subject = subjectRepository.findByName(subjectName);
        if(subject.isPresent()){
            Subject _subject = subject.get();
            teacherRegistryRepository.deleteAll(teacherRegistryRepository.findBySubject(_subject));
            subjectRepository.delete(_subject);
        }

    }

    /*Adott tantárgyat tanárhoz és osztályhoz rendelhetünk. Ekkor új tanári bejegyzést is létrehozunk,
    valamint az osztály tanulóinak grade-bejegyzéseket (Előfordulhat, hogy korábban már volt ilyen tárgyuk, de tanár vagy
    tantárgy-törlés miatt eltávolítottuk, ezért hozzáadáskor mindenkire ellenőrizzük, hogy van -e ilyen tartárgyhoz
     bejegyzése
     */
    @Transactional
    public void addToClassAndTeacher(Subject subject, Sclass sclass, User user){

        if(user.getUserrole() == Role.ROLE_Teacher ||
        user.getUserrole() == Role.ROLE_ClassHead){
            TeacherRegistry teacherRegistry = new TeacherRegistry();
            teacherRegistry.setSubject(subject);
            teacherRegistry.setSclass(sclass);
            teacherRegistry.setTeacher(user);

            subject.getTeacherRegistries().add(teacherRegistry);
            sclass.getTeacherRegistries().add(teacherRegistry);
            user.getTeacherRegistries().add(teacherRegistry);

            teacherRegistryRepository.save(teacherRegistry);

            List<Student> students = studentRepository.findBySclass(sclass);

            for(Student student: students){
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

        } else throw new RuntimeException();

    }

    //Ha az előzőből hiányosság lép fel (pl. hozzáadáskor nem jelent meg minden szükséges jegybejegyzés,
    //itt pótolhatjuk:
    @Transactional
    public void replenishGradeDatas(Subject subject, Sclass sclass, User user){
        if(user.getUserrole() == Role.ROLE_Teacher ||
                user.getUserrole() == Role.ROLE_ClassHead){
            List<Student> students = studentRepository.findBySclass(sclass);

            for(Student student: students){
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
        }
        else throw new RuntimeException();
    }

    public void validate(Subject subject, Sclass sclass){

        if (teacherRegistryRepository.findBySubjectAndSclass(subject,sclass).isPresent())
         throw new RuntimeException("Az osztálynak már van ilyen tantárgya!");
    }

    @Transactional
    public void deleteRegistry(TeacherRegistry teacherRegistry){
        teacherRegistryRepository.delete(teacherRegistry);
    }

    @Transactional
    public void deleteAllRegistries(){
        teacherRegistryRepository.deleteAll();
    }
}
