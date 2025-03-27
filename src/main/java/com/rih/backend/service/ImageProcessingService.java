package com.rih.backend.service;

import org.opencv.core.Mat;
import org.opencv.core.Size;
import org.opencv.imgcodecs.Imgcodecs;
import org.opencv.imgproc.Imgproc;
import org.springframework.stereotype.Service;

import nu.pattern.OpenCV;

@Service
public class ImageProcessingService {
    static {
        OpenCV.loadLocally();
    }

    public Mat preprocessImage(String imagePath) {
        Mat image = Imgcodecs.imread(imagePath);

        if (image.empty()) {
            throw new IllegalArgumentException("Error: Cannot load image!");
        }

        Mat gray = new Mat();
        Imgproc.cvtColor(image, gray, Imgproc.COLOR_BGR2GRAY);

        Mat resized = new Mat();
        Imgproc.resize(gray, resized, new Size(224, 224));

        return resized;
    }
}
