FROM gradle:6.1.1-jdk13 AS cache
RUN mkdir -p /home/gradle/cache_home
ENV GRADLE_USER_HOME /home/gradle/cache_home
COPY build.gradle /home/gradle/src/
WORKDIR /home/gradle/src
RUN gradle clean build --no-daemon --build-cache

FROM gradle:6.1.1-jdk13 AS build
EXPOSE 8080
COPY --from=cache /home/gradle/cache_home /home/gradle/.gradle
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build --no-daemon 

FROM openjdk:13.0.2-slim
EXPOSE 8080
RUN mkdir app
COPY --from=build /home/gradle/src/build/libs/*.jar /app/dataloader.jar
CMD [ "java","-jar","/app/dataloader.jar"]
# ENTRYPOINT ["java", "-jar","/app/dataloader.jar"]
