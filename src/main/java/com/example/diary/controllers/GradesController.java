package com.example.diary.controllers;

import com.example.diary.models.*;
import com.example.diary.services.GradesService;
import com.example.diary.services.SclassService;
import com.example.diary.services.StudentService;
import com.example.diary.services.SubjectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/grades")
public class GradesController {

    @Autowired
    private GradesService gradesService;

    @Autowired
    private SubjectService subjectService;

    @Autowired
    private SclassService sclassService;

    @Autowired
    private StudentService studentService;

    @GetMapping("/first")
    public ResponseEntity<?> getGrades1(
            @RequestParam(required = true) String subjectName,
            @RequestParam(required = true) String className){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Sclass sclass = sclassService.findByName(className);

            List<Grades1> grades1List = gradesService.findBySubjectandClass1(subject,sclass);

            Map<String,Object> response = new HashMap<>();
            response.put("grades1",grades1List);
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e){return new ResponseEntity<>("A tantárgy vagy osztály nem található!",HttpStatus.NOT_FOUND);}
        catch (Exception e2){ return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }
    }

    @GetMapping("/second")
    public ResponseEntity<?> getGrades2(
            @RequestParam(required = true) String subjectName,
            @RequestParam(required = true) String className){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Sclass sclass = sclassService.findByName(className);

            List<Grades2> grades2List = gradesService.findBySubjectandClass2(subject,sclass);
            Map<String,Object> response = new HashMap<>();
            response.put("grades2",grades2List);
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e){return new ResponseEntity<>("A tantárgy vagy osztály nem található!",HttpStatus.NOT_FOUND);}
        catch (Exception e2){ return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @GetMapping("/final")
    public ResponseEntity<?> getFinalGrades(
            @RequestParam(required = true) String subjectName,
            @RequestParam(required = true) String className){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Sclass sclass = sclassService.findByName(className);

            List<FinalGrades> finalGradesList = gradesService.findBySubjectandClassF(subject,sclass);
            Map<String,Object> response = new HashMap<>();
            response.put("finalgrades",finalGradesList);
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e){return new ResponseEntity<>("A tantárgy vagy osztály nem található!",HttpStatus.NOT_FOUND);}
        catch (Exception e2){ return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @GetMapping("/first/{id}")
    public ResponseEntity<?> getStudentGrades1(
            @PathVariable("id") Integer id){
        try {
            Student student = studentService.find(id);
            List<Grades1> grades1List = gradesService.findByStudent1(student);

            return new ResponseEntity<>(grades1List, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>("Helytelen keresési adat!",HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @GetMapping("/second/{id}")
    public ResponseEntity<?> getStudentGrades2(
            @PathVariable("id") Integer id){
        try {
            Student student = studentService.find(id);
            List<Grades2> grades2List = gradesService.findByStudent2(student);

            return new ResponseEntity<>(grades2List, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>("Helytelen keresési adat!",HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @GetMapping("/final/{id}")
    public ResponseEntity<?> getStudentFinalGrades(
            @PathVariable("id") Integer id){
        try {
            Student student = studentService.find(id);
            List<FinalGrades> finalGradesList = gradesService.findByStudentF(student);

            return new ResponseEntity<>(finalGradesList, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>("Helytelen keresési adat!",
                HttpStatus.NOT_FOUND);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/first/add/{id}")
    public ResponseEntity<?> addGrade1(@RequestParam(required = true) String subjectName,
                                      @RequestParam(required = true) int grade,
                                       @RequestParam(required = true) int module,
                                      @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.addGrade1(student,subject,module,grade);

            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("module", module);
            response.put("grade", grade);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.NOT_FOUND);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/second/add/{id}")
    public ResponseEntity<?> addGrade2(@RequestParam(required = true) String subjectName,
                                       @RequestParam(required = true) int grade,
                                       @RequestParam(required = true) int module,
                                       @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.addGrade2(student,subject,module,grade);

            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("module", module);
            response.put("grade", grade);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.NOT_FOUND);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/first/delete/{id}")
    public ResponseEntity<?> deleteGrade1(@RequestParam(required = true) String subjectName,
                                          @RequestParam(required = true) int module,
                                      @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.removeGrade1(student,subject,module);

            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("module", module);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.NOT_FOUND);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/second/delete/{id}")
    public ResponseEntity<?> deleteGrade2(@RequestParam(required = true) String subjectName,
                                          @RequestParam(required = true) int module,
                                          @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.removeGrade2(student,subject,module);

            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("module", module);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.NOT_FOUND);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/first/calc/{id}")
    public ResponseEntity<?> calculateModule1(@RequestParam(required = true) String subjectName,
                                              @RequestParam(required = true) int module,
                                         @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.calculateModule1(student,subject,module);


            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("module", module);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/second/calc/{id}")
    public ResponseEntity<?> calculateModule2(@RequestParam(required = true) String subjectName,
                                              @RequestParam(required = true) int module,
                                              @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.calculateModule2(student,subject,module);


            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("module", module);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/first/semester/{id}")
    public ResponseEntity<?> calculateSemester1(@RequestParam(required = true) String subjectName,
                                             @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.calculateSemester1(student,subject);


            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("semester", 1);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("/second/semester/{id}")
    public ResponseEntity<?> calculateSemester2(@RequestParam(required = true) String subjectName,
                                                @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.calculateSemester2(student,subject);


            Map<String,Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("semester", 2);


            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("final/grade/{id}")
    public ResponseEntity<?> calculateYear(@RequestParam(required = true) String subjectName,
                                           @PathVariable("id") Integer id){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.calculateFinalGrade(student, subject);

            Map<String, Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);

            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }

    @PutMapping("final/exam/{id}")
    public ResponseEntity<?> giveExamGrade(@RequestParam(required = true) String subjectName,
                                           @RequestParam(required = true) int grade,
                                           @PathVariable("id") Integer id
                                           ){
        try {
            Subject subject = subjectService.findByName(subjectName);
            Student student = studentService.find(id);

            gradesService.addExam(student,subject,grade);

            Map<String, Object> response = new HashMap<>();
            response.put("student",student.getName());
            response.put("subject",subjectName);
            response.put("grade ", grade);

            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (RuntimeException e)
        {return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);}
        catch (Exception e2)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }

    }






}
