package com.example.diary.controllers;


import com.example.diary.Security.UserDetailsImpl;
import com.example.diary.Security.jwt.JwtUtils;
import com.example.diary.dto.AuthenticationDTO;
import com.example.diary.dto.UserDTO;
import com.example.diary.models.Role;
import com.example.diary.models.User;
import com.example.diary.repositories.UserRepository;
import com.example.diary.util.UserValidator;
import jakarta.validation.Valid;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
@RestController
@RequestMapping("/api/auth")
public class AuthController {

  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;


  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @Autowired
  UserValidator userValidator;

  @Autowired
  ModelMapper modelMapper;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@RequestBody @Valid  AuthenticationDTO authDTO,
                                            BindingResult bindingResult) {

      if(!userRepository.existsByName(authDTO.getUsername()))
        return ResponseEntity.badRequest().body("Érvénytelen felhasználónév!");

      try{
          Authentication authentication = authenticationManager.authenticate(
                  new UsernamePasswordAuthenticationToken(authDTO.getUsername(), authDTO.getPassword()));

          SecurityContextHolder.getContext().setAuthentication(authentication);
          String jwt = jwtUtils.generateJwtToken(authentication);
          UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
          Collection<? extends GrantedAuthority> role = userDetails.getAuthorities();


          Map<String,Object> response = new HashMap<>();
          response.put("username", userDetails.getUser().toString());
          response.put("role",userDetails.getAuthorities().stream()
                  .map(item -> item.getAuthority()));

          if(role.toString().contains(Role.ROLE_Parent.toString()));
          response.put("children",userDetails.getChildren().stream()
                  .map(item -> item.getAuthority()));

          if(role.toString().contains(Role.ROLE_Teacher.toString()) || role.toString().contains(Role.ROLE_ClassHead.toString()));
          response.put("subjects",userDetails.getSubjects().stream()
                  .map(item -> item.getAuthority()));

          if(role.toString().contains(Role.ROLE_Teacher.toString()) || role.toString().contains(Role.ROLE_ClassHead.toString()));
          response.put("learning",userDetails.getSubjectRepositories().stream()
                  .map(item -> item.getAuthority()));

          if(role.toString().contains(Role.ROLE_ClassHead.toString()));
          response.put("class",userDetails.getClasses().stream()
                  .map(item -> item.getAuthority()));

          return ResponseEntity.ok(response);
      } catch (AuthenticationException e) {
          return ResponseEntity.badRequest().body("Helytelen jelszó!");
      }
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody UserDTO userDTO, BindingResult bindingResult) {

   User user = convertToUser(userDTO);

   user.setPassword(encoder.encode(userDTO.getPassword()));
   user.setUserrole(Role.ROLE_Visitor);
   user.setCreatedAt(LocalDateTime.now());

   userValidator.validate(user, bindingResult);
   if(bindingResult.hasErrors()) return ResponseEntity.badRequest()
           .body("Regisztrációs hiba: " + bindingResult.getFieldErrors().stream().map(e -> e.getDefaultMessage()).collect(Collectors.joining(", ")));

   userRepository.save(user);

    Map<String, String> response = new HashMap<>();
    response.put("message", "Új felhasználó: " + user.getName());
    return ResponseEntity.ok(response);
  }

  @PostMapping("/signout")
  public ResponseEntity<?> signoutUser() {
    if(SecurityContextHolder.getContext().getAuthentication() != null){
      UserDetailsImpl userDetails
              = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
      SecurityContextHolder.getContext().setAuthentication(null);
      return ResponseEntity.ok("Kijelentkezve: " + userDetails.getUsername());
    } else return ResponseEntity.badRequest().body("Még nem jelentkezett be!");
  }

  @GetMapping("/schoolYear")
  public ResponseEntity<?> getSchoolYear() throws IOException {
      RandomAccessFile file = new RandomAccessFile("src/main/resources/data.txt","r");
      String s = file.readLine();
      file.close();
      Map<String,Object> response = new HashMap<>();
      response.put("schoolYear",s);
      return ResponseEntity.ok(response);
  }

  private User convertToUser(UserDTO personDTO) {
    return this.modelMapper.map(personDTO, User.class);
  }
}
