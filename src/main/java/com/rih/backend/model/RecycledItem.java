package com.rih.backend.model;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Entity representing a recycled item in the Recycling Intelligence Hub (RIH) project.
 * This entity stores details about recycled products, including their category, material type, and processing details.
 */
@Entity
@Table(name = "recycled_item")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RecycledItem {

    /**
     * Unique identifier for the recycled item.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Unique code assigned to the recycled item.
     */
    private String code;

    /**
     * Classification of the recycled item (e.g., Plastic, Metal, Paper, Glass).
     */
    private String classification;

    /**
     * Timestamp indicating when the recycled item was registered.
     */
    private LocalDateTime timeStamp;
}
