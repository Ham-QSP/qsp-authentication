QSP Authentication application is a core module of the QSP platform. 
This application provides OAuth authentication for users. 

# Running this project
## From the sources
### Requirements
- Java 25+
- Maven
- Postgresql 17+

### Setup 
Setup the database connection. As example by environment variable:
```
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/qsp
SPRING_DATASOURCE_USERNAME=qsp
SPRING_DATASOURCE_PASSWORD=qsp_password
```

### Run
Start the application with:
```shell
mvn spring-boot:run -f pom.xml
```