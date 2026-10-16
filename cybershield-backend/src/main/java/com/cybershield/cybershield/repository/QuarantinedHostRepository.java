package com.cybershield.cybershield.repository;

import com.cybershield.cybershield.model.QuarantinedHost;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface QuarantinedHostRepository extends JpaRepository<QuarantinedHost, Long> {

    Optional<QuarantinedHost> findByIpAndActiveTrue(String ip);

    Optional<QuarantinedHost> findByIp(String ip);

    List<QuarantinedHost> findByActiveTrueOrderByIdDesc();

    boolean existsByIpAndActiveTrue(String ip);

    long countByActiveTrue();
}
