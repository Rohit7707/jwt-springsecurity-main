package com.ust.Security.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Job {
    @Id
    public int id;
    public String jobtitle;
    public String jobdescription;
    public String joblocation;
    public String jobtype;
    public String jobposteddate;
    public String jobskills;
    public String jobexperience;
    public String jobpackage;
}
