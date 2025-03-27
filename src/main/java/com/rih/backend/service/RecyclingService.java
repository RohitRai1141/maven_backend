package com.rih.backend.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.rih.backend.dto.RecycledItemDto;
import com.rih.backend.model.RecycledItem;
import com.rih.backend.repository.RecycledItemRepository;

@Service
public class RecyclingService {
    @Autowired
    private RecycledItemRepository repository;

    public void saveRecycledItem(RecycledItemDto dto) {
        RecycledItem item = RecycledItem.builder()
                .code(dto.getCode())
                .classification(dto.getClassification())
                .timeStamp(LocalDateTime.now())
                .build();

        repository.save(item);
    }

    public List<RecycledItemDto> getAllRecycledItems() {
        return repository.findAll().stream()
                .map(item -> new RecycledItemDto(item.getCode(), item.getClassification()))
                .collect(Collectors.toList());
    }
}
