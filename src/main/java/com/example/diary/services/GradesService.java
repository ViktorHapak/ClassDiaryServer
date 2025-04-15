package com.example.diary.services;

import com.example.diary.models.*;
import com.example.diary.repositories.FinalGradesRepository;
import com.example.diary.repositories.Grades1Repository;
import com.example.diary.repositories.Grades2Repository;
import com.example.diary.repositories.StudentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class GradesService {

    @Autowired
    private Grades1Repository grades1Repository;

    @Autowired
    private Grades2Repository grades2Repository;

    @Autowired
    private FinalGradesRepository finalGradesRepository;
    @Autowired
    private StudentRepository studentRepository;

    @Transactional
    public void add1(Grades1 grades1){
        grades1Repository.save(grades1);
    }

    @Transactional
    public void add2(Grades2 grades2){
        grades2Repository.save(grades2);
    }

    @Transactional
    public void addF(FinalGrades finalgrades){
        finalGradesRepository.save(finalgrades);
    }


    //Repository függvények a Grades-bejegyzések visszakereséséhez tanuló és tantárgy alapján
    public List<Grades1> findStudent1(Student student){
        return grades1Repository.findByStudent(student);
    }

    public List<Grades1> findSubject1(Subject subject){
        return grades1Repository.findBySubjectName(subject.getName());
    }

    public List<Grades2> findStudent2(Student student){
        return grades2Repository.findByStudent(student);
    }

    public List<Grades2> findSubject2(Subject subject){
        return grades2Repository.findBySubjectName(subject.getName());
    }

    public List<FinalGrades> findStudentF(Student student){
        return finalGradesRepository.findByStudent(student);
    }

    public List<FinalGrades> findSubjectF(Subject subject){
        return finalGradesRepository.findBySubjectName(subject.getName());
    }

    public List<Grades1> findBySubjectandClass1(Subject subject, Sclass sclass){
        return grades1Repository.findBySubjectName(subject.getName()).stream().filter(el ->
                el.getStudent().getSclass() == sclass).collect(Collectors.toUnmodifiableList());
    }

    public List<Grades2> findBySubjectandClass2(Subject subject, Sclass sclass){
        return grades2Repository.findBySubjectName(subject.getName()).stream().filter(el ->
                el.getStudent().getSclass() == sclass).collect(Collectors.toUnmodifiableList());
    }

    public List<FinalGrades> findBySubjectandClassF(Subject subject, Sclass sclass){
        return finalGradesRepository.findBySubjectName(subject.getName()).stream().filter(el ->
                el.getStudent().getSclass() == sclass).collect(Collectors.toUnmodifiableList());
    }

    public List<Grades1> findByStudent1(Student student){
        return grades1Repository.findAll().stream().filter(el ->
                el.getStudent() == student).collect(Collectors.toUnmodifiableList());
    }

    public List<Grades2> findByStudent2(Student student){
        return grades2Repository.findAll().stream().filter(el ->
                el.getStudent() == student).collect(Collectors.toUnmodifiableList());
    }

    public List<FinalGrades> findByStudentF(Student student){
        return finalGradesRepository.findAll().stream().filter(el ->
                el.getStudent() == student).collect(Collectors.toUnmodifiableList());
    }



    //Jegy osztásakor a megfelelő modul,tárgy és tanuló jegyeihez(karakterlánc) adjuk hozzá a jegyet
    @Transactional
    public void addGrade1(Student student, Subject subject, int module, int grade){
        String subjectName = subject.getName();

        if(grades1Repository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        //if(module<1 || module>3) throw new RuntimeException("Érvénytelen modul!");

        if(grade<1 || grade>5) throw new RuntimeException("Érvénytelen jegy!");

        Grades1 grades1 = grades1Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        switch (module){
            case 1:{
                if (grades1.getModulegrades1() == null) grades1.setModulegrades1(""); break;
            }
            case 2: {
                if (grades1.getModulegrades2() == null) grades1.setModulegrades2(""); break;
            }
            case 3: {
                if (grades1.getModulegrades3() == null) grades1.setModulegrades3(""); break;
            }
            default: throw new RuntimeException("Érvénytelen modul!");
        }

        switch (module){
            case 1: grades1.setModulegrades1((grades1.getModulegrades1().equals(""))?
                    (grade + ""):(grades1.getModulegrades1() + " " + grade)); break;
            case 2: grades1.setModulegrades2((grades1.getModulegrades2().equals("") || grades1.getModulegrades2() == null)?
                    (grade + ""):(grades1.getModulegrades2() + " " + grade)); break;
            case 3: grades1.setModulegrades3((grades1.getModulegrades3().equals("") || grades1.getModulegrades3() == null)?
                    (grade + ""):(grades1.getModulegrades3() + " " + grade)); break;
            default: throw new RuntimeException("Érvénytelen modul!");
        }

        grades1Repository.save(grades1);
    }

    @Transactional
    public void addGrade2(Student student, Subject subject, int module, int grade){
        String subjectName = subject.getName();

        if(grades2Repository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        //if(module<1 || module>3) throw new RuntimeException("Érvénytelen modul!");

        if(grade<1 || grade>5) throw new RuntimeException("Érvénytelen jegy!");

        Grades2 grades2 = grades2Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        switch (module){
            case 1:{
                if (grades2.getModulegrades1() == null) grades2.setModulegrades1(""); break;
            }
            case 2: {
                if (grades2.getModulegrades2() == null) grades2.setModulegrades2(""); break;
            }
            case 3: {
                if (grades2.getModulegrades3() == null) grades2.setModulegrades3(""); break;
            }
            default: throw new RuntimeException("Érvénytelen modul!");
        }

        switch (module){
            case 1: grades2.setModulegrades1((grades2.getModulegrades1().equals(""))?
                    (grade + ""):(grades2.getModulegrades1() + " " + grade)); break;
            case 2: grades2.setModulegrades2((grades2.getModulegrades2().equals(""))?
                    (grade + ""):(grades2.getModulegrades2() + " " + grade)); break;
            case 3: grades2.setModulegrades3((grades2.getModulegrades3().equals(""))?
                    (grade + ""):(grades2.getModulegrades3() + " " + grade)); break;
            default: throw new RuntimeException("Érvénytelen modul!");
        }

        grades2Repository.save(grades2);
    }

    //A modul utolsó jegyét is törölni tudjuk substring-képzéssel.
    @Transactional
    public void removeGrade1(Student student, Subject subject, int module){
        String subjectName = subject.getName();

        if(grades1Repository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        Grades1 grades1 = grades1Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        switch (module){
            case 1:{
                if (grades1.getModulegrades1() == null) grades1.setModulegrades1(""); break;
            }
            case 2: {
                if (grades1.getModulegrades2() == null) grades1.setModulegrades2(""); break;
            }
            case 3: {
                if (grades1.getModulegrades3() == null) grades1.setModulegrades3(""); break;
            }
            default: throw new RuntimeException("Érvénytelen modul!");
        }

        switch (module){
            case 1:{
                if (grades1.getModulegrades1().equals(""))
                    throw new RuntimeException("Még nincs modulhoz tartozó jegye!");

                List<String> gradeList = new ArrayList<String>(Arrays.asList(grades1.getModulegrades1().split(" ")));
                gradeList.remove(gradeList.size()-1);
                grades1.setModulegrades1(String.join(" ",gradeList));
                break;
            }
            case 2:{
                if (grades1.getModulegrades2().equals(""))
                throw new RuntimeException("Még nincs modulhoz tartozó jegye!");

                List<String> gradeList = new ArrayList<String>(Arrays.asList(grades1.getModulegrades2().split(" ")));
                gradeList.remove(gradeList.size()-1);
                grades1.setModulegrades2(String.join(" ",gradeList));
                break;
            }
            case 3:{
                if (grades1.getModulegrades3().equals(""))
                    throw new RuntimeException("Még nincs modulhoz tartozó jegye!");

                List<String> gradeList = new ArrayList<String>(Arrays.asList(grades1.getModulegrades3().split(" ")));
                gradeList.remove(gradeList.size()-1);
                grades1.setModulegrades3(String.join(" ",gradeList));
                break;
            }
            default: throw new RuntimeException("Érvénytelen modul!");
        }
        grades1Repository.save(grades1);
    }

    @Transactional
    public void removeGrade2(Student student, Subject subject, int module){
        String subjectName = subject.getName();

        if(grades2Repository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        Grades2 grades2 = grades2Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        switch (module){
            case 1:{
                if (grades2.getModulegrades1() == null) grades2.setModulegrades1(""); break;
            }
            case 2: {
                if (grades2.getModulegrades2() == null) grades2.setModulegrades2(""); break;
            }
            case 3: {
                if (grades2.getModulegrades3() == null) grades2.setModulegrades3(""); break;
            }
            default: throw new RuntimeException("Érvénytelen modul!");
        }

        switch (module){
            case 1:{
                if (grades2.getModulegrades1().equals("") || grades2.getModulegrades1() == null)
                    throw new RuntimeException("Még nincs modulhoz tartozó jegye!");

                List<String> gradeList = new ArrayList<String>(Arrays.asList(grades2.getModulegrades1().split(" ")));
                gradeList.remove(gradeList.size()-1);
                grades2.setModulegrades1(String.join(" ",gradeList));
                break;
            }
            case 2:{
                if (grades2.getModulegrades2().equals("") || grades2.getModulegrades2() == null)
                    throw new RuntimeException("Még nincs modulhoz tartozó jegye!");

                List<String> gradeList = new ArrayList<String>(Arrays.asList(grades2.getModulegrades2().split(" ")));
                gradeList.remove(gradeList.size()-1);
                grades2.setModulegrades2(String.join(" ",gradeList));
                break;
            }
            case 3:{
                if (grades2.getModulegrades3().equals("") || grades2.getModulegrades3() == null)
                    throw new RuntimeException("Még nincs modulhoz tartozó jegye!");

                List<String> gradeList = new ArrayList<String>(Arrays.asList(grades2.getModulegrades3().split(" ")));
                gradeList.remove(gradeList.size()-1);
                grades2.setModulegrades3(String.join(" ",gradeList));
                break;
            }
            default: throw new RuntimeException("Érvénytelen modul!");
        }
        grades2Repository.save(grades2);
    }

    @Transactional
    public void calculateModule1(Student student, Subject subject, int module){
        String subjectName = subject.getName();

        if(grades1Repository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        Grades1 grades1 = grades1Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        switch (module){
            case 1: {
                if (grades1.getModulegrades1() == null)
                 throw new RuntimeException("Ennél a modulnál nincs még jegy");

                if (grades1.getModulegrades1().trim().equals(""))
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                List<Integer> gradeList = new ArrayList<String>(Arrays.asList(grades1.getModulegrades1().split(" ")))
                        .stream().map(e -> Integer.parseInt(e)).collect(Collectors.toUnmodifiableList());

                int sum = 0; int db = 0;
                for(int grade: gradeList){
                    sum = sum + grade;
                    db++;
                }
                double q = (double) sum/(double) db;
                int avarage = (int) Math.round(q);
                double fraction = (q - (double) avarage)+1;
                if(fraction==0.5) grades1.setModule1(avarage-1);
                else grades1.setModule1(avarage);
                break;}
            case 2: {
                if (grades1.getModulegrades2() == null)
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                if (grades1.getModulegrades2().trim().equals(""))
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                List<Integer> gradeList = new ArrayList<String>(Arrays.asList(grades1.getModulegrades2().split(" ")))
                        .stream().map(e -> Integer.parseInt(e)).collect(Collectors.toUnmodifiableList());

                int sum = 0; int db = 0;
                for(int grade: gradeList){
                    sum = sum + grade;
                    db++;
                }
                double q = (double) sum/(double) db;
                int avarage = (int) Math.round(q);
                double fraction = (q - (double) avarage)+1;
                if(fraction==0.5) grades1.setModule2(avarage-1);
                else grades1.setModule2(avarage);
                break; }
            case 3: {
                if (grades1.getModulegrades3() == null)
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                if (grades1.getModulegrades3().trim().equals(""))
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                List<Integer> gradeList = new ArrayList<String>(Arrays.asList(grades1.getModulegrades3().split(" ")))
                        .stream().map(e -> Integer.parseInt(e)).collect(Collectors.toUnmodifiableList());

                int sum = 0; int db = 0;
                for(int grade: gradeList){
                    sum = sum + grade;
                    db++;
                }
                double q = (double) sum/(double) db;
                int avarage = (int) Math.round(q);
                double fraction = (q - (double) avarage)+1;
                if(fraction==0.5) grades1.setModule3(avarage-1);
                else grades1.setModule3(avarage);
                break; }
            default: throw new RuntimeException("Érvénytelen modul!");
        }
        grades1Repository.save(grades1);

    }

    @Transactional
    public void calculateModule2(Student student, Subject subject, int module){
        String subjectName = subject.getName();

        if(grades2Repository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        Grades2 grades2 = grades2Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        switch (module){
            case 1: {
                if (grades2.getModulegrades1() == null)
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                if (grades2.getModulegrades1().trim().equals(""))
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                List<Integer> gradeList = new ArrayList<String>(Arrays.asList(grades2.getModulegrades1().split(" ")))
                        .stream().map(e -> Integer.parseInt(e)).collect(Collectors.toUnmodifiableList());

                int sum = 0; int db = 0;
                for(int grade: gradeList){
                    sum = sum + grade;
                    db++;
                }
                double q = (double) sum/(double) db;
                int avarage = (int) Math.round(q);
                double fraction = (q - (double) avarage)+1;
                if(fraction==0.5) grades2.setModule1(avarage-1);
                else grades2.setModule1(avarage);
                break;}
            case 2: {
                if (grades2.getModulegrades2() == null)
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                if (grades2.getModulegrades2().trim().equals(""))
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                List<Integer> gradeList = new ArrayList<String>(Arrays.asList(grades2.getModulegrades2().split(" ")))
                        .stream().map(e -> Integer.parseInt(e)).collect(Collectors.toUnmodifiableList());

                int sum = 0; int db = 0;
                for(int grade: gradeList){
                    sum = sum + grade;
                    db++;
                }
                double q = (double) sum/(double) db;
                int avarage = (int) Math.round(q);
                double fraction = (q - (double) avarage)+1;
                if(fraction==0.5) grades2.setModule2(avarage-1);
                else grades2.setModule2(avarage);
                break; }
            case 3: {
                if (grades2.getModulegrades3() == null)
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                if (grades2.getModulegrades3().trim().equals(""))
                    throw new RuntimeException("Ennél a modulnál nincs még jegy");

                List<Integer> gradeList = new ArrayList<String>(Arrays.asList(grades2.getModulegrades3().split(" ")))
                        .stream().map(e -> Integer.parseInt(e)).collect(Collectors.toUnmodifiableList());

                int sum = 0; int db = 0;
                for(int grade: gradeList){
                    sum = sum + grade;
                    db++;
                }
                double q = (double) sum/(double) db;
                int avarage = (int) Math.round(q);
                double fraction = (q - (double) avarage)+1;
                if(fraction==0.5) grades2.setModule3(avarage-1);
                else grades2.setModule3(avarage);
                break; }
            default: throw new RuntimeException("Érvénytelen modul!");
        }
        grades2Repository.save(grades2);

    }

    //Ha minden modul megvan, kiszámíthatjuk a félévi jegyet
    @Transactional
    public void calculateSemester1(Student student, Subject subject){
        String subjectName = subject.getName();

        if(grades1Repository.findByStudentAndSubjectName(student,subjectName).isEmpty()
        || finalGradesRepository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        Grades1 grades1 = grades1Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);
        FinalGrades finalGrades = finalGradesRepository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        if(grades1.getModule1() == null || grades1.getModule2() == null || grades1.getModule3() == null)
            throw new RuntimeException("Hiányzó témazáró!");

        if(grades1.getModule1() == 0 || grades1.getModule2() == 0 || grades1.getModule3() == 0)
            throw new RuntimeException("Hiányzó témazáró!");

        int sum = grades1.getModule1()+grades1.getModule2()+grades1.getModule3();
        double q = ((double) sum)/3;
        int avarage = (int) Math.round(q);
        double fraction = (q - (double) avarage)+1;
        if(fraction==0.5) grades1.setSemester(avarage-1);
        else grades1.setSemester(avarage);

        grades1Repository.save(grades1);

        finalGrades.setGrade1(grades1.getSemester());
        finalGradesRepository.save(finalGrades);
    }

    @Transactional
    public void calculateSemester2(Student student, Subject subject){
        String subjectName = subject.getName();

        if(grades2Repository.findByStudentAndSubjectName(student,subjectName).isEmpty() ||
        finalGradesRepository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        Grades2 grades2 = grades2Repository.findByStudentAndSubjectName(student,subjectName).orElse(null);
        FinalGrades finalGrades = finalGradesRepository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        if(grades2.getModule1() == null || grades2.getModule2() == null || grades2.getModule3() == null)
            throw new RuntimeException("Hiányzó témazáró!");

        if(grades2.getModule1() == 0 || grades2.getModule2() == 0 || grades2.getModule3() == 0)
            throw new RuntimeException("Hiányzó témazáró!");

        int sum = grades2.getModule1()+grades2.getModule2()+grades2.getModule3();
        double q = ((double) sum)/3;
        int avarage = (int) Math.round(q);
        double fraction = (q - (double) avarage)+1;
        if(fraction==0.5) grades2.setSemester(avarage-1);
        else grades2.setSemester(avarage);

        grades2Repository.save(grades2);

        finalGrades.setGrade2(grades2.getSemester());
        finalGradesRepository.save(finalGrades);
    }

    @Transactional
    public void addExam(Student student, Subject subject, int grade){
        String subjectName = subject.getName();
        if(finalGradesRepository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        FinalGrades finalGrades = finalGradesRepository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        if(finalGrades.getGrade1()==null || finalGrades.getGrade2()==null)
            throw new RuntimeException("Számítsa ki a két félévet!");

        if(finalGrades.getGrade1()==0 || finalGrades.getGrade2()==0)
            throw new RuntimeException("Számítsa ki a két félévet!");

        if(grade<1 || grade>5) throw new RuntimeException("Érvénytelen jegy!");

        finalGrades.setExam(grade);
        finalGradesRepository.save(finalGrades);
    }

    @Transactional
    public void calculateFinalGrade(Student student, Subject subject){
        String subjectName = subject.getName();
        if(finalGradesRepository.findByStudentAndSubjectName(student,subjectName).isEmpty())
            throw new RuntimeException("Érvényes tanulót és tárgyat adjon meg!");

        FinalGrades finalGrades = finalGradesRepository.findByStudentAndSubjectName(student,subjectName).orElse(null);

        if(finalGrades.getGrade1()==null || finalGrades.getGrade2()==null)
            throw new RuntimeException("Számítsa ki a két félévet!");

        if(finalGrades.getGrade1()==0 || finalGrades.getGrade2()==0)
            throw new RuntimeException("Számítsa ki a két félévet!");

        if(finalGrades.getExam() == null) finalGrades.setExam(0);

        double q;
        if(finalGrades.getExam() == 0) q = ((double) (finalGrades.getGrade1() + finalGrades.getGrade2() )) /2;
        else q = ((double) (finalGrades.getGrade1() + finalGrades.getGrade2() + finalGrades.getExam())) /3;

        int avarage = (int) Math.round(q);
        double fraction = (q - (double) avarage)+1;
        if(fraction==0.5) finalGrades.setGrade(avarage-1);
        else finalGrades.setGrade(avarage);

        finalGradesRepository.save(finalGrades);

    }

    @Transactional
    public void deleteAllGrades(){
        studentRepository.findAll().stream().forEach(e->{
                e.setGrades1List(null);
                e.setGrades2List(null);
                e.setFinalgrades1List(null);
                studentRepository.save(e);}
        );

        grades1Repository.deleteAll(grades1Repository.findAll());
        grades2Repository.deleteAll(grades2Repository.findAll());
        finalGradesRepository.deleteAll(finalGradesRepository.findAll());
    }


}

