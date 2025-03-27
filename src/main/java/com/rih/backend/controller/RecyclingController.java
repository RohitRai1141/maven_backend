package com.rih.backend.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.rih.backend.dto.RecycledItemDto;
import com.rih.backend.service.BarcodeAndQRScannerService;
import com.rih.backend.service.RecyclingService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/api/recycling")
public class RecyclingController {

    @Autowired
    private RecyclingService recyclingService;

    @Autowired
    private BarcodeAndQRScannerService scannerService;

    @PostMapping("/image-processing")
    public String saveItem(@RequestParam("image") MultipartFile imageFile) {
        if (imageFile.isEmpty()) {
            return "No image uploaded!";
        }

        System.out.println("Hello");

        try {
            String scannedCode = scannerService.scanCode(imageFile.getBytes());

            if (scannedCode == null || scannedCode.isEmpty()) {
                return "No barcode or QR code detected!";
            }

            RecycledItemDto dto = new RecycledItemDto();
            dto.setCode(scannedCode);
            dto.setClassification("Unknown");

            recyclingService.saveRecycledItem(dto);

            return "Scanned item saved successfully!";
        } catch (IOException e) {
            return "Error processing image: " + e.getMessage();
        }
    }

    @GetMapping("/history")
    public List<RecycledItemDto> getAllRecycledItems() {
        return recyclingService.getAllRecycledItems();
    }
}
