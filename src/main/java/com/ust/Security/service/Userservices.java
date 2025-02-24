package com.ust.Security.service;


import com.ust.Security.model.Userinfo;
import com.ust.Security.repository.Userinforepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class Userservices {
    @Autowired
    private Userinforepository repo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    public String addUser(Userinfo userInfo) {
        userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
        repo.save(userInfo);
        return "user added to system ";
    }
    public Userinfo findByEmail(String email) {
        return repo.findByEmail(email);
    }
    
    public void updatePassword(Userinfo user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        repo.save(user);
    }
}
