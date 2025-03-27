# Use an official JDK 21 base image
FROM eclipse-temurin:21-jdk

# Install OpenCV 4.9.0 and dependencies
RUN apt-get update && apt-get install -y \
    libopencv-dev \
    && rm -rf /var/lib/apt/lists/*

# Set OpenCV library path
ENV LD_LIBRARY_PATH=/usr/lib:/usr/lib/jni:/usr/local/lib:/usr/lib/x86_64-linux-gnu

#ENV JWT_SECRET_KEY=""
#ENV SECURITY_JWT_EXPIRATION_TIME=3600000

# Copy the application JAR file
COPY target/backend-0.0.1-SNAPSHOT.jar /app/backend.jar

# Set the working directory
WORKDIR /app

# Run the application with OpenCV configured
ENTRYPOINT ["java", "-Djava.library.path=/usr/lib:/usr/lib/jni:/usr/local/lib:/usr/lib/x86_64-linux-gnu", "-jar", "backend.jar"]
