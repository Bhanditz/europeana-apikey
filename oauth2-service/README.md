# Example Oauth2 Service with a trusted client # 

The Oauth2 service is based on Spring boot and can be started with **mvn spring-boot:run**. An in memory oauth2 client is
created with one configured username/password (user/test) which is configured in the [authorizationServer.yml](src/main/resources/authorizationServer.yml).
The Oauth2 service runs on port 8888.
The Oauth2 service produces JWT tokens, after a successfull login. These tokens should be used with the secured REST API.

The client is run by starting the SimpleTestClient (in the client folder). This start a simple REST controller on port 8082 
that is secured by oauth. It requires a Bearer token (JWT) in the header (that is retrieved from the oauth server)

Finally we have a trustedclient, that retrieves a token from the oauth server using the credentials. This client will 
automatically request new access tokens using the refresh token after expiration of the access token.

# MVC client # 

The MVC client based on Spring boot and can be started with **mvn spring-boot:run** from the **mvcclient** folder. It will start as service on port 8080.
This MVC app secured using oauth. Requesting a secured web page will result in a login page from the oauth server.
