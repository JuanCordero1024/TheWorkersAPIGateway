# ----------------------------------------------------------------------
# 1. BUILD STAGE: Compila el proyecto con Maven y JDK 21
# ----------------------------------------------------------------------
FROM maven:3.9.6-eclipse-temurin-21 AS build

# Directorio de trabajo
WORKDIR /app

# Copia el POM y descarga dependencias (para usar caché)
COPY pom.xml .
RUN mvn dependency:go-offline

# Copia el código fuente
COPY src ./src

# Compila el proyecto y genera el JAR
RUN mvn clean package -DskipTests

# Verifica que el JAR se haya generado
RUN ls -l target

# ----------------------------------------------------------------------
# 2. RUNTIME STAGE: Imagen ligera con JRE 21
# ----------------------------------------------------------------------
FROM eclipse-temurin:21-jre-alpine

# Directorio de trabajo en tiempo de ejecución
WORKDIR /app

# Define el nombre del archivo JAR (ajústalo si cambia en tu pom.xml)
ARG JAR_FILE=TheworkersGateway-0.0.1-SNAPSHOT.jar

# Copia el JAR desde la etapa build
COPY --from=build /app/target/${JAR_FILE} app.jar

# Expone el puerto de la aplicación
EXPOSE 8080

# Comando de arranque
ENTRYPOINT ["java", "-jar", "app.jar"]
