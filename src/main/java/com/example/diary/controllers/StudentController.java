package com.example.diary.controllers;

import com.example.diary.models.Sclass;
import com.example.diary.models.Student;
import com.example.diary.models.Subject;
import com.example.diary.services.SclassService;
import com.example.diary.services.StudentService;
import com.example.diary.services.SubjectService;
import com.example.diary.util.StudentValidator;
import jakarta.validation.Valid;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/data/students")
public class StudentController {

    @Autowired
    private StudentService studentService;

    @Autowired
    private SclassService sclassService;

    @Autowired
    private SubjectService subjectService;

    @Autowired
    ModelMapper modelMapper;

    @Autowired
    private StudentValidator studentValidator;

    @GetMapping("/all")
    public ResponseEntity<?> getAllStudents (){
        try{
        List<Student> students = studentService.findAll();

        if(students.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

        return new ResponseEntity<>(students, HttpStatus.OK);
    } catch (Exception e) {
        return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    }

    @GetMapping("/allPageByClassAndName")
    public ResponseEntity<?> getAllStudentsPageByClassAndName(
            @RequestParam(required = false) String className,
            @RequestParam(required = false) String title,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "5") int size
    ) {
        try{
        Pageable paging = PageRequest.of(page, size);
        Page<Student> studentPage;

        if (className==null || className.isEmpty()) {
            if (title == null) studentPage = studentService.findAllPage(paging);
            else studentPage = studentService.findByNamePage(title, paging);
        }
        else if (className.equals("null")){
            if(title == null) studentPage = studentService.findIfNoClassPage(paging);
            else  studentPage = studentService.findIfNoClassByNamePage(title,paging);
        }
        else{
            try{
                Sclass sclass = sclassService.findByName(className);
                if (title == null) studentPage = studentService.findByClassPage(className, paging);
                else studentPage = studentService.findByClassAndNamePage(className,title,paging);
            }
            catch (RuntimeException e) {return new ResponseEntity<>("Hibás keresési adat!",HttpStatus.NOT_FOUND);}
        }
        List<Student> students = studentPage.getContent();


        Map<String, Object> response = new HashMap<>();
        if(className!=null) response.put("Class: ", className);
        response.put("students", students);
        response.put("totalItems", studentPage.getTotalElements());
        response.put("starting_at", studentPage.getNumber());
        response.put("totalPages", studentPage.getTotalPages());

        return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getStudentById(@PathVariable("id") Integer id) {
        try {
            Student student = studentService.find(id);
            return ResponseEntity.ok(student);
        } catch (RuntimeException e) {
            return new ResponseEntity<>("A tanuló nem létezik!", HttpStatus.NOT_FOUND);
        }

    }

    @PostMapping("/")
    public ResponseEntity<?> createStudent(@RequestBody @Valid Student student, BindingResult bindingResult){
        try {
            Student _student = new Student(student.getName(), student.getBirth(), student.getAddress());
            studentValidator.validate(_student, bindingResult);

            if(bindingResult.hasErrors()) return ResponseEntity.badRequest()
                    .body("A hozzáadás sikertelen: " + bindingResult.getFieldErrors().stream()
                            .map(e -> e.getDefaultMessage()).collect(Collectors.joining(", ")));

            studentService.save(_student);

            Map<String, Object> response = new HashMap<>();
            response.put("name", _student.getName());

            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>("A tanuló hozzáadása sikertelen", HttpStatus.INTERNAL_SERVER_ERROR);
        }



    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateStudent(@RequestBody @Valid Student student,
                                           @PathVariable Integer id,
                                           BindingResult bindingResult){
        try{
            Student _student = studentService.find(id);

            _student.setName(student.getName());
            _student.setBirth(student.getBirth());
            _student.setAddress(student.getAddress());

            if(student.getInfo() != null) _student.setInfo(student.getInfo());

            studentValidator.validate(_student, bindingResult);
            if(bindingResult.hasErrors()) return ResponseEntity.badRequest()
                    .body("A módosítás sikertelen: " + bindingResult.getFieldErrors().stream()
                            .map(e -> e.getDefaultMessage()).collect(Collectors.joining(", ")));

            studentService.save(_student);
            return ResponseEntity.ok(_student);
        } catch (Exception e){
            return new ResponseEntity<>("A módosítás sikertelen!", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/toClass/{id}")
    public ResponseEntity<?> addToClass(@RequestParam(required = true) String className,
                                        @PathVariable Integer id){
        try{
            Sclass sclass = sclassService.findByName(className);
            Student _student = studentService.find(id);
            studentService.addToClass(_student,sclass);

            Map<String, Object> response = new HashMap<>();
            response.put("name", _student.getName());
            response.put("sclass", className);
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (RuntimeException e) {
            return new ResponseEntity<>("Nincs ilyen tanuló vagy osztály!", HttpStatus.NOT_FOUND);
        }
    }

    @PutMapping("/fromClass/{id}")
    public ResponseEntity<?> removeFromClass(@PathVariable Integer id){
        try{
            Student _student = studentService.find(id);
            String sclassName = _student.getSclass().getName();
            studentService.deleteFromClass(_student);

            Map<String, Object> response = new HashMap<>();
            response.put("name", _student.getName());
            response.put("sclass", "null");
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        } catch (RuntimeException e) {
            return new ResponseEntity<>("Nem tartozik egyik osztályhoz sem!", HttpStatus.NOT_FOUND);
        }
    }


    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteStudent(@PathVariable("id") Integer id) {
        try {
            Student student = studentService.find(id);
            studentService.delete(student);
            Map<String,Object> response = new HashMap<>();
            return new ResponseEntity<>("A tanuló eltávolítva", HttpStatus.NO_CONTENT);
        } catch (RuntimeException e){
            return new ResponseEntity<>("Nincs ilyen tanuló", HttpStatus.NOT_FOUND);
        }
        catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/all")
    public ResponseEntity<?> deleteAllStudents(@RequestParam(required = false) String className) {
        try {
            if(className == null) {
                studentService.deleteAll();
                return new ResponseEntity<>("Minden tanuló eltávolítva",HttpStatus.NO_CONTENT);
            } else{
                try {
                    Sclass sclass = sclassService.findByName(className);
                    studentService.deleteAllFromClass(sclass);
                    return new ResponseEntity<>("Minden tanuló eltávolítva az osztályból: " +sclass.getName(),HttpStatus.NO_CONTENT);
                } catch (RuntimeException e){ return new ResponseEntity<>("Nincs ilyen osztály", HttpStatus.NOT_FOUND);}

            }
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }


    @PostMapping("/class")
    public ResponseEntity<?> createClass(@RequestParam(defaultValue = "1") String year){
        try{

            String newClass = sclassService.addClass(Integer.parseInt(year));
            Map<String,Object> response = new HashMap<>();
            response.put("Új osztály",newClass);
            return new ResponseEntity<>(response, HttpStatus.CREATED);

        }
        catch (RuntimeException e1) {
            return ResponseEntity.badRequest().body(e1.getMessage());
        }catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/classes")
    public ResponseEntity<?> getAllClasses(@RequestParam(required = false) String subjectName) {
        try{
            List<Sclass> classes;
            if(subjectName == null || subjectName.equals("")) {
                classes = sclassService.findAll();
                if(classes.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);
                return new ResponseEntity<>(classes, HttpStatus.OK);
            } else {
                Subject subject = subjectService.findByName(subjectName);
                classes =  sclassService.findBySubject(subject);
                if(classes.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);
                return new ResponseEntity<>(classes, HttpStatus.OK);
            }
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }



    @DeleteMapping("/class")
    public ResponseEntity<?> removeClass(@RequestParam(required = true)String className){
        try{
            Sclass sclass = sclassService.findByName(className);

            int StudentNumber = sclassService.deleteClass(sclass);

            return new ResponseEntity<>("Az osztály eltávolítva. " + StudentNumber +
                    " tanuló maradt osztály nélkül", HttpStatus.NO_CONTENT);
        } catch (RuntimeException e){
            return new ResponseEntity<>("Nincs ilyen osztály!",HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }














}
