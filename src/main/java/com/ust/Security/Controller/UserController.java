package com.ust.Security.Controller;


import com.ust.Security.dto.AuthRequest;
import com.ust.Security.model.Job;
import com.ust.Security.model.Userinfo;
import com.ust.Security.service.Jobservice;
import com.ust.Security.service.JwtService;
import com.ust.Security.service.Userservices;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class UserController {
    @Autowired
    private Userservices service;
    @Autowired
    private Jobservice jobservice;
    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/adduser")
    public String addNewUser(@RequestBody  @Valid Userinfo user){
        return service.addUser(user);
    }
    @PostMapping("/addjob")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Job addjob(@RequestBody Job job){
        return jobservice.addjob(job);
    }

    @GetMapping("/getalljobs")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public List<Job> getalljobs(){
        return jobservice.getalljobs();
    }

    //login endpoint
    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(authRequest.getUsername());
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }


    }



}
