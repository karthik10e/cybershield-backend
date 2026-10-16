package com.cybershield.cybershield.repository;

import com.cybershield.cybershield.model.SecurityIncident;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, Long> {

    List<SecurityIncident> findTop50ByOrderByIdDesc();

    List<SecurityIncident> findTop500ByOrderByIdDesc();

    long countByIsAttackTrue();

    long countByAttackType(String attackType);
}
