package com.ust.Security.service;

import com.ust.Security.model.Job;
import com.ust.Security.repository.Jobrepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class Jobservice {
    @Autowired
    private Jobrepository repo;
    public Job addjob(Job job) {
        return repo.save(job);
    }

    public List<Job> getalljobs() {
        return repo.findAll();
    }
}
