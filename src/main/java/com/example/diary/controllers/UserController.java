package com.example.diary.controllers;

import com.example.diary.models.Role;
import com.example.diary.models.Sclass;
import com.example.diary.models.Student;
import com.example.diary.models.User;
import com.example.diary.services.SclassService;
import com.example.diary.services.StudentService;
import com.example.diary.services.SubjectService;
import com.example.diary.services.UserService;
import com.example.diary.util.UserValidator;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLDataException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("api/data/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private StudentService studentService;

    @Autowired
    private SubjectService subjectService;

    @Autowired
    private SclassService sclassService;

    @Autowired
    PasswordEncoder encoder;
    @Autowired
    private UserValidator userValidator;

    @GetMapping("/all")
    public ResponseEntity<?> getAllUsers (){
        try{
            List<User> users = userService.findAll();

            if(users.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

            Map<String,Object> response = new HashMap<>();
            response.put("users", users);

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/allByPage")
    public ResponseEntity<?> getAllUsersPage(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "5") int size,
            @RequestParam(defaultValue = "") String title,
            @RequestParam(defaultValue = "all") String roleName

    ) {
        try{
            Pageable paging = PageRequest.of(page, size);
            Page<User> userPage;

            if(roleName.equals("all") || roleName.isEmpty()){
                userPage = userService.findByName(title, paging);
            } else if (roleName.equals("teachers")) {
                userPage = userService.findTeachersByName(title,paging);
            }
            else {
                try {
                    Role role = Role.valueOf(roleName);
                    userPage = userService.findByRoleAndName(role,title,paging);
                } catch (IllegalArgumentException e) {
                    return new ResponseEntity<>("Érvénytelen felhasználó szerep",
                            HttpStatus.BAD_REQUEST);
                }
            }

            List<User> users = userPage.getContent();

            //if(users.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

            Map<String, Object> response = new HashMap<>();
            response.put("users", users);
            response.put("starting at", userPage.getNumber());
            response.put("totalItems", userPage.getTotalElements());
            response.put("totalPages", userPage.getTotalPages());

            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/byName")
    public ResponseEntity<?> getAllUsersByName(
            @RequestParam(required = true) String title
    ) {
        try{
            List<User> users = userService.findByName(title);

            //if(users.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

            Map<String, Object> response = new HashMap<>();
            response.put("users", users);
            return new ResponseEntity<>(response, HttpStatus.OK);
        }catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/byRole")
    public ResponseEntity<?> getUsersByRole(
            @RequestParam(required = true) String roleName
    ){
        try { Role role = Role.valueOf(roleName);
        List<User> users = userService.findByRole(role);

        if(users.isEmpty()) return new ResponseEntity<>("Üres lista", HttpStatus.NO_CONTENT);

        return new ResponseEntity<>(users, HttpStatus.OK);}
        catch (IllegalArgumentException e)
         {
        return new ResponseEntity<>("Érvénytelen felhasználó szerep", HttpStatus.BAD_REQUEST);
         }
        catch (Exception e){
          return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable("id") Integer id) {
        try {
            User user = userService.find(id);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>("A felhasználó nem létezik!", HttpStatus.NOT_FOUND);
        }

    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@RequestBody @Valid User user,
                                           @PathVariable Integer id,
                                           BindingResult bindingResult){
        try{
            User _user = userService.find(id);

            _user.setFirstname(user.getFirstname());
            _user.setLastname(user.getLastname());
            _user.setEmail(user.getEmail());
            _user.setName(user.getName());
            _user.setBirth(user.getBirth());

            userValidator.validate(_user, bindingResult);
            if(bindingResult.hasErrors())
                if(bindingResult.hasErrors()) return ResponseEntity.badRequest()
                        .body("A módosítás sikertelen: " + bindingResult.getFieldErrors().stream()
                                .map(e -> e.getDefaultMessage()).collect(Collectors.joining(", ")));

            userService.save(_user);
            return ResponseEntity.ok(_user);
        } catch (RuntimeException e){
            return new ResponseEntity<>("A frissítés sikertelen!", HttpStatus.NOT_FOUND);
        }
    }

    @PutMapping("/parent/{id}")
    private ResponseEntity<?> addParentRole(@PathVariable("id") Integer id,
                                            @RequestParam(required = true) String childName) {
        try {
            User parent = userService.find(id);
            Student child = studentService.findStudentByName(childName);

            String message = userService.setParentRole(parent, child);
            if(message.equals("")){
                Map<String,Object> response = new HashMap<>();
                response.put("parent",parent.getName());
                response.put("children",childName);
                return new ResponseEntity<>(response,HttpStatus.OK);
            }
            else return ResponseEntity.badRequest().body(message);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/parent/{id}/new")
    private ResponseEntity<?> addChildren(@PathVariable("id") Integer id,
                                            @RequestParam(required = true) String childName) {
        try {
            User parent = userService.find(id);
            Student child = studentService.findStudentByName(childName);

            String message = userService.addChildren(parent,child);
            if(message.equals("")){
            Map<String,Object> response = new HashMap<>();
            response.put("parent",parent.getName());
            response.put("children",childName);
                return new ResponseEntity<>(response,HttpStatus.OK);
            }
            else return ResponseEntity.badRequest().body(message);


        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/classhead/{id}")
    private ResponseEntity<?> addClassHeadRole(@PathVariable("id") Integer id,
                                            @RequestParam(required = true) String className) {
        try {
            User classhead = userService.find(id);
            Sclass _sclass = sclassService.findByName(className);

            userService.setClassHeadRole(classhead,_sclass);
            Map<String,Object> response = new HashMap<>();
            response.put("classhead",classhead.getName());
            response.put("class",_sclass.getName());
            return ResponseEntity.ok(response);


        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/classhead/{id}/new")
    private ResponseEntity<?> addClass(@PathVariable("id") Integer id,
                                               @RequestParam(required = true) String className) {
        try {
            User classhead = userService.find(id);
            Sclass _sclass = sclassService.findByName(className);

            userService.addClass(classhead,_sclass);

            Map<String,Object> response = new HashMap<>();
            response.put("classhead",classhead.getName());
            response.put("children",_sclass.getName());

            return ResponseEntity.ok(response);


        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/teacher/{id}")
    private ResponseEntity<?> addTeacherRole(@PathVariable("id") Integer id){
        try{
            User teacher = userService.find(id);

            userService.setTeacherRole(teacher);

            Map<String,Object> response = new HashMap<>();
            response.put("teacher",teacher.getName());

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/admin/{id}")
    private ResponseEntity<?> addAdminRole(@PathVariable("id") Integer id){
        try{
            User admin = userService.find(id);

            userService.setAdminRole(admin);

            Map<String,Object> response = new HashMap<>();
            response.put("admin",admin.getName());

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/visitor/{id}")
    private ResponseEntity<?> addVisitorRole(@PathVariable("id") Integer id){
        try{
            User user = userService.find(id);

            userService.setVisitorRole(user);

            Map<String,Object> response = new HashMap<>();
            response.put("visitor",user.getName());

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable("id") Integer id) {
        try {
            User user = userService.find(id);
            userService.delete(user);
            return new ResponseEntity<>("A felhasználó eltávolítva", HttpStatus.NO_CONTENT);
        } catch (RuntimeException e){
            return new ResponseEntity<>("Nincs ilyen felhasználó", HttpStatus.NOT_FOUND);
        }
        catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }








}
