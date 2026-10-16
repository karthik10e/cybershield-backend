package com.cybershield.cybershield.repository;

import com.cybershield.cybershield.model.UrlScanResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UrlScanResultRepository extends JpaRepository<UrlScanResult, Long> {

    List<UrlScanResult> findTop20ByOrderByIdDesc();
}
