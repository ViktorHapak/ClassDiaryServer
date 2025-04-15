package com.example.diary.services;

import com.example.diary.models.Role;
import com.example.diary.models.Sclass;
import com.example.diary.models.Student;
import com.example.diary.models.User;
import com.example.diary.repositories.SclassRepository;
import com.example.diary.repositories.TeacherRegistryRepository;
import com.example.diary.repositories.UserRepository;
import jakarta.validation.constraints.Null;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SclassRepository sclassRepository;

    @Autowired
    private TeacherRegistryRepository teacherRegistryRepository;


    @Autowired
    private PasswordEncoder encoder;

    @Transactional
    public void save(User user) {
        userRepository.save(user);
    }

    public User find(Integer id){
        return userRepository.findById(id).orElseThrow(RuntimeException::new);
    }

    public Page<User> findAllPage(Pageable pageable){
        return userRepository.findAll(pageable);
    }

    public User findTeacherByName(String name) {
        User teacher = userRepository.findByName(name).orElseThrow(RuntimeException::new);
        if(teacher.getUserrole() != Role.ROLE_Teacher && teacher.getUserrole() != Role.ROLE_ClassHead)
            throw new RuntimeException("Nincs ilyen tanár!");

        return teacher;
    }

    public List<User> findAll(){
        return userRepository.findAll();
    }

    public Page<User> findPage(Pageable pageable){
        return userRepository.findAll(pageable);
    }

    public List<User> findByName(String name){
        return userRepository.findByNameStartingWith(name);
    }

    public List<User> findByRole(Role role){
        return userRepository.findByUserrole(role);
    }

    public Page<User> findByRoleAndName(Role role, String name, Pageable pageable){
        return userRepository.findByUserroleAndNameStartingWith(role, name, pageable);
    }

    public Page<User> findTeachersByName(String name, Pageable paging) {
        List<User> teacherList;

        if(name.equals(" ")) teacherList = userRepository.findAll().stream().filter(user ->
                user.getUserrole().equals(Role.ROLE_Teacher) ||
                        user.getUserrole().equals(Role.ROLE_ClassHead)
        ).collect(Collectors.toList());

            else teacherList = userRepository.findByNameStartingWith(name).stream().filter(user ->
                user.getUserrole().equals(Role.ROLE_Teacher) ||
                        user.getUserrole().equals(Role.ROLE_ClassHead)

        ).collect(Collectors.toList());

        return new PageImpl<>(teacherList,paging,5);
    }

    public Page<User> findByName(String name, Pageable pageable){
        return userRepository.findByNameStartingWith(name, pageable);
    }

    @Transactional
    public void update(Integer id, User user){
        Optional<User> userToUpdate = Optional.ofNullable(userRepository.findById(id).orElseThrow(RuntimeException::new));

        if(userToUpdate.isPresent()){
            User _user = userToUpdate.get();
            _user.setFirstname(user.getFirstname());
            _user.setLastname(user.getLastname());
            _user.setEmail(user.getEmail());
            _user.setName(user.getName());
            _user.setBirth(user.getBirth());

            userRepository.save(_user);
        }
    }

    @Transactional
    public String setParentRole(User user, Student student){
        if(user.getUserrole() != Role.ROLE_Visitor)
            return  "A felhasználónak már van jogosultsága: " + user.getUserrole().toString();
        else if(student.getParents().stream().count() >= 2)
            return  "Ennek a diáknak már vannak szülei!";
             else {
                 user.setUserrole(Role.ROLE_Parent);
                 user.getChildren().add(student);
                 student.getParents().add(user);
                 userRepository.save(user);
                 return "";

             }
    }

    @Transactional
    public String addChildren(User user, Student student){
        if(user.getUserrole() != Role.ROLE_Parent)
            return "A felhasználó nem rendelkezik Parent jogosultsággal!";
        else if(student.getParents().stream().count() >= 2)
                return "Ennek a diáknak már vannak szülei!";
            else {
                user.getChildren().add(student);
                student.getParents().add(user);
                userRepository.save(user);
                return "";
            }

    }


    @Transactional
    public void setTeacherRole(User user){
        if(user.getUserrole() != Role.ROLE_Visitor && user.getUserrole() != Role.ROLE_ClassHead)
            throw new RuntimeException("A felhasználónak már van jogosultsága: " + user.getUserrole().toString());
        else{
            if(user.getUserrole() == Role.ROLE_ClassHead){
                user.getSclass().setClassteacher(null);
                user.setSclass(null);
            }
            user.setUserrole(Role.ROLE_Teacher);
            userRepository.save(user);

        }

    }

    @Transactional
    public void setClassHeadRole(User user, Sclass sclass){
        if (user.getUserrole() != Role.ROLE_Visitor && user.getUserrole() != Role.ROLE_Teacher)
            throw new RuntimeException("A felhasználónak már van jogosultsága: " + user.getUserrole().toString());
        else if(sclass.getClassteacher() != null)
            throw new RuntimeException("Ennek az osztálynak már van osztályfőnöke!");
        else if(user.getSclass() != null)
            throw new RuntimeException("Már van osztálya!");
        else {
            user.setUserrole(Role.ROLE_ClassHead);
            user.setSclass(sclass);
            sclass.setClassteacher(user);
            userRepository.save(user);
        }

    }

    @Transactional
    public void addClass(User user, Sclass sclass){
        if(user.getUserrole() != Role.ROLE_ClassHead)
            throw new RuntimeException("A felhasználó nem rendelkezik CLASS_HEAD jogosultsággal!");
        else if(sclass.getClassteacher() != null)
            throw new RuntimeException("Ennek az osztálynak már van osztályfőnöke!");
        else if(user.getSclass() != null)
            throw new RuntimeException("Már van osztálya!");
        else {
            user.setSclass(sclass);
            sclass.setClassteacher(user);
            userRepository.save(user);
        }

    }

    @Transactional
    public void setAdminRole(User user){
        if(user.getUserrole() != Role.ROLE_Visitor)
            throw new RuntimeException("A felhasználónak már van jogosultsága: " + user.getUserrole().toString());
        else if(userRepository.findByUserrole(Role.ROLE_Admin).stream().count()>=3)
            throw new RuntimeException("Egyszerre csak 3 admin-ja lehet az intézménynek!");
        else{
            user.setUserrole(Role.ROLE_Admin);
            userRepository.save(user);
        }
    }

    @Transactional
    public String setVisitorRole(User user){

        if(user.getUserrole() == Role.ROLE_ClassHead
        && user.getSclass() != null){
            user.getSclass().setClassteacher(null);
            user.setSclass(null);
        }

        /*user.getChildren().stream().forEach(e->{e.getParents().remove(user);});
        user.setChildren(null);*/

        for (Student student : user.getChildren()) {
            student.getParents().remove(user);
        }
        user.getChildren().clear();

        teacherRegistryRepository.deleteAll(teacherRegistryRepository.findByTeacher(user));

        user.setUserrole(Role.ROLE_Visitor);

        userRepository.save(user);
        return "A " + user.getName() + " " + user.getPassword() + " felhasználó megvált a szerepétől!";
    }

    @Transactional
    public void delete(User user) {

        if(user.getUserrole() == Role.ROLE_ClassHead
        && user.getSclass() != null){
            user.getSclass().setClassteacher(null);
            user.setSclass(null);
        }

        /*user.getChildren().stream().forEach(e->{e.getParents().remove(user);});
        user.setChildren(null);*/

        for (Student student : user.getChildren()) {
            student.getParents().remove(user);
        }
        user.getChildren().clear();

        teacherRegistryRepository.deleteAll(teacherRegistryRepository.findByTeacher(user));

        userRepository.delete(user);
    }


}
