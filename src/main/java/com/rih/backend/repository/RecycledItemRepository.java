package com.rih.backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rih.backend.model.RecycledItem;

public interface RecycledItemRepository extends JpaRepository<RecycledItem, Long> {

    
}
