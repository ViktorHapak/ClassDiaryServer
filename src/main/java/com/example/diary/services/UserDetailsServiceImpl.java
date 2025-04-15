package com.example.diary.services;


import com.example.diary.Security.UserDetailsImpl;
import com.example.diary.models.User;
import com.example.diary.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  @Autowired
  UserRepository userRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByName(username)
        .orElseThrow(() -> new UsernameNotFoundException("Nincs ilyen felhasználónév: " + username));

    return new UserDetailsImpl(user);
  }

}
