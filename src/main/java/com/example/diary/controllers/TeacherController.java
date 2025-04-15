package com.example.diary.controllers;

import com.example.diary.models.*;
import com.example.diary.services.GradesService;
import com.example.diary.services.SclassService;
import com.example.diary.services.SubjectService;
import com.example.diary.services.UserService;
import com.example.diary.util.SchoolYearDAO;
import com.example.diary.util.SubjectValidator;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("api/data/subjects")
public class TeacherController {

    @Autowired
    private SubjectService subjectService;

    @Autowired
    private UserService userService;

    @Autowired
    private SclassService sclassService;

    @Autowired
    private GradesService gradesService;

    @Autowired
    private SubjectValidator subjectValidator;

    @Autowired
    private SchoolYearDAO schoolYearDAO;


    @GetMapping("/")
    public ResponseEntity<?> getAllRegistries(@RequestParam(defaultValue = "subject") String sortField,
                                               @RequestParam(defaultValue = "asc") String sortDirection,
                                                   @RequestParam(defaultValue = "0") int page,
                                               @RequestParam(defaultValue = "5") int size){
        try {

            Sort sort = sortDirection.equals("asc") ? Sort.by(Sort.Direction.ASC, sortField)
                    : Sort.by(Sort.Direction.DESC, sortField);
            Pageable pageable = PageRequest.of(page, size, sort);
            Page<TeacherRegistry> registriesPage = subjectService.findAllRegistry(pageable);

            List<TeacherRegistry> registries = registriesPage.getContent();

            //if (registries.isEmpty()) return new ResponseEntity<>(null, HttpStatus.NO_CONTENT);

            Map<String, Object> response = new HashMap<>();
            response.put("registries", registries);
            response.put("starting at", registriesPage.getNumber());
            response.put("totalItems", registriesPage.getTotalElements());
            response.put("totalPages", registriesPage.getTotalPages());

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e)
        { return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }
    }

    @GetMapping("/bySubject")
    public ResponseEntity<?> getRegistriesBySubject(@RequestParam(defaultValue = "sclass") String sortField,
                                                    @RequestParam(defaultValue = "asc") String sortDirection,
                                                    @RequestParam(required = true) String subjectName,
                                                     @RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "5") int size){
        try {
            Subject subject = subjectService.findByName(subjectName);

            Sort sort = sortDirection.equals("asc") ? Sort.by(Sort.Direction.ASC, sortField)
                    : Sort.by(Sort.Direction.DESC, sortField);
            Pageable pageable = PageRequest.of(page, size,sort);
            Page<TeacherRegistry> registriesPage = subjectService.findRegistriesBySubject(subject,
                    pageable);

            List<TeacherRegistry> registries = registriesPage.getContent();

            if (registries.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

            Map<String, Object> response = new HashMap<>();
            response.put("registries", registries);
            response.put("starting at", registriesPage.getNumber());
            response.put("totalItems", registriesPage.getTotalElements());
            response.put("totalPages", registriesPage.getTotalPages());

            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e){return new ResponseEntity<>("A tantárgy nem található!",HttpStatus.NOT_FOUND);}
        catch (Exception e2){ return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }
    }

    @GetMapping("/byTeacher")
    public ResponseEntity<?> getRegistriesByTeacher(@RequestParam(defaultValue = "sclass") String sortField,
                                                    @RequestParam(defaultValue = "asc") String sortDirection,
                                                    @RequestParam(required = true) String teacherName,
                                                     @RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "5") int size){
        try {
            User teacher = userService.findTeacherByName(teacherName);

            Sort sort = sortDirection.equals("asc") ? Sort.by(Sort.Direction.ASC, sortField)
                    : Sort.by(Sort.Direction.DESC, sortField);
            Pageable pageable = PageRequest.of(page, size, sort);
            Page<TeacherRegistry> registriesPage = subjectService.findRegistriesByTeacher(teacher,
                    pageable);

            List<TeacherRegistry> registries = registriesPage.getContent();

            if (registries.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

            Map<String, Object> response = new HashMap<>();
            response.put("registries", registries);
            response.put("starting at", registriesPage.getNumber());
            response.put("totalItems", registriesPage.getTotalElements());
            response.put("totalPages", registriesPage.getTotalPages());

            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e){return new ResponseEntity<>("A tanár nem található!",HttpStatus.NOT_FOUND);}
        catch (Exception e2){ return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }
    }

    @GetMapping("/byClass")
    public ResponseEntity<?> getRegistriesByClass(@RequestParam(defaultValue = "teacher") String sortField,
                                                  @RequestParam(defaultValue = "asc") String sortDirection,
                                                  @RequestParam(required = true) String className,
                                                   @RequestParam(defaultValue = "0") int page,
                                                   @RequestParam(defaultValue = "5") int size){
        try {
            Sclass sclass = sclassService.findByName(className);


            Sort sort = sortDirection.equals("asc") ? Sort.by(Sort.Direction.ASC, sortField)
                    : Sort.by(Sort.Direction.DESC, sortField);
            Pageable pageable = PageRequest.of(page, size, sort);
            Page<TeacherRegistry> registriesPage = subjectService.findRegistriesByClass(sclass,
                    pageable);

            List<TeacherRegistry> registries = registriesPage.getContent();

            if (registries.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

            Map<String, Object> response = new HashMap<>();
            response.put("registries", registries);
            response.put("starting at", registriesPage.getNumber());
            response.put("totalItems", registriesPage.getTotalElements());
            response.put("totalPages", registriesPage.getTotalPages());

            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        catch (RuntimeException e){return new ResponseEntity<>("Az osztály nem található!",HttpStatus.NOT_FOUND);}
        catch (Exception e2){ return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); }
    }

    @PostMapping("/")
    public ResponseEntity<?> createSubject(@RequestBody @Valid Subject subject, BindingResult bindingResult){
        try{
            Subject _subject = new Subject(subject.getName());

            subjectValidator.validate(_subject, bindingResult);
            if(bindingResult.hasErrors())
                return ResponseEntity.badRequest()
                    .body("A hozzáadás sikertelen: " + bindingResult.getFieldErrors().stream()
                            .map(e -> e.getDefaultMessage()).collect(Collectors.joining(", ")));

            subjectService.save(_subject);
            Map<String,Object> response = new HashMap<>();
            response.put("subject", _subject.getName());
            return ResponseEntity.ok().body(response);
        } catch (Exception e){
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/subject/all")
    public ResponseEntity<?> getSubjects( @RequestParam(defaultValue = "") String className,
                                          @RequestParam(defaultValue = "") String subjectName,
                                          @RequestParam(defaultValue = "0") int page,
                                          @RequestParam(defaultValue = "5") int size){
        try{
        Pageable pageable = PageRequest.of(page, size);
            Page<Subject> subjectPage;
        if (className.equals("")){
            subjectPage = subjectService.findAllSubjectByName(subjectName,pageable);
        } else {
            Sclass sclass = sclassService.findByName(className);
            subjectPage = subjectService.findAllSubjectByNameAndClass(sclass, subjectName, pageable);
        }


        List<Subject> subjects = subjectPage.getContent();

        //if (subjects.isEmpty()) return new ResponseEntity<>(null, HttpStatus.NO_CONTENT);

        Map<String, Object> response = new HashMap<>();
        response.put("subjects", subjects);
        response.put("starting at", subjectPage.getNumber());
        response.put("totalItems", subjectPage.getTotalElements());
        response.put("totalPages", subjectPage.getTotalPages());

        return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e)
        {
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }


    @GetMapping("/subject/{id}")
    public ResponseEntity<?> getSubjectById(@PathVariable int id){
        try {
            Subject subject = subjectService.find(id);
            return ResponseEntity.ok(subject);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body("Nincs ilyen tárgy!");
        }

    }

    @DeleteMapping("/")
    public ResponseEntity<?> deleteSubject(@RequestParam(required = true) String subjectName) {
        try {
            subjectService.delete(subjectName);
            return new ResponseEntity<>("A tantárgy eltávolítva", HttpStatus.NO_CONTENT);
        } catch (RuntimeException e){
            return new ResponseEntity<>("Nincs ilyen tárgy", HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/registry")
    public ResponseEntity<?> createRegistry(
            @RequestParam(required = true) String teacherName,
            @RequestParam(required = true) String subjectName,
            @RequestParam(required = true) String className
    ){
        try {
            User teacher = userService.findTeacherByName(teacherName);
            Subject subject = subjectService.findByName(subjectName);
            Sclass sclass = sclassService.findByName(className);

            try {
                subjectService.validate(subject, sclass);
            } catch (RuntimeException e) {
                return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
            }

            TeacherRegistry teacherRegistry = new TeacherRegistry(teacher, subject, sclass);

            subjectService.addToClassAndTeacher(subject,sclass,teacher);

            Map<String, Object> response = new HashMap<>();
            response.put("teacher", teacherName);
            response.put("subject", subjectName);
            response.put("sclass", sclass.getName());

            return new ResponseEntity<>(response,HttpStatus.CREATED);

        } catch (RuntimeException e) {
            return new ResponseEntity<>("Helytelen tantárgy-, tanár vagy osztálynév.", HttpStatus.NOT_FOUND);
        } catch (Exception e){
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }

    @DeleteMapping("/registry/{id}")
    public ResponseEntity<?> deleteRegistry(@PathVariable("id") Integer id) {
        try {
            TeacherRegistry teacherRegistry = subjectService.findRegistryById(id);
            subjectService.deleteRegistry(teacherRegistry);
            return new ResponseEntity<>("A tanári viszony eltávolítva", HttpStatus.NO_CONTENT);
        } catch (RuntimeException e){
            return new ResponseEntity<>("Nincs ilyen tanári viszony", HttpStatus.NOT_FOUND);
        }
        catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/registry/all")
    public ResponseEntity<?> deleteAllRegistries() {
        try {
            subjectService.deleteAllRegistries();
            return new ResponseEntity<>("Minden tanári viszony eltávolítva", HttpStatus.NO_CONTENT);
        } catch (RuntimeException e){
            return new ResponseEntity<>("Nincs ilyen tanári viszony", HttpStatus.NOT_FOUND);
        }
        catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/schoolYear")
    public ResponseEntity<?> getSchoolYear() {
        try {

            SchoolYear schoolYear = schoolYearDAO.getSchoolYearObject();

            Map<String, Object> response = new HashMap<>();
            response.put("schoolYear", schoolYear.getYear());
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e){
            return new ResponseEntity<>("", HttpStatus.BAD_REQUEST);
        }
        catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PutMapping("/newSchoolYear")
    public ResponseEntity<?> beginSchoolYear() {
        try {

            SchoolYear schoolYear = schoolYearDAO.getSchoolYearObject();
            SchoolYear newSchoolYear = schoolYearDAO.defineSchoolYear();

            Map<String, Object> response = new HashMap<>();
            response.put("OldSchoolYear", schoolYear.getYear());
            response.put("NewSchoolYear", newSchoolYear.getYear());

            if(newSchoolYear.getYear().equals(schoolYear.getYear())){
                response.put("changed", "no");
            } else {
                response.put("changed", "yes");
                sclassService.increaseYear();
                subjectService.deleteAllRegistries();
                gradesService.deleteAllGrades();
            }
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e){
            return new ResponseEntity<>("", HttpStatus.BAD_REQUEST);
        }
        catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
