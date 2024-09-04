# SSLValidator

## Description

This project is a Maven-based application designed to validate and test secure communication using SSL/TLS protocols. It can validate SSL/TLS connections using different parameters including mutual TLS (mTLS), cipher suites, and various key and trust stores and helps identify issues if SSL connection fails.

## Getting Started

### Prerequisites

- Java JDK 11 or later
- Maven 3.9.0 or later
- Access to a terminal or command prompt

### Compiling the Project

To compile the project, follow these steps:

1. Open a terminal or command prompt.
2. Navigate to the project's root directory.
3. Run the following Maven command:

```shell
mvn clean compile assembly:single
```

This command compiles the project and produces a runnable artifact if compilation is successful.

### Running the Application

To run the application, execute the following command in the terminal from the project's root directory:

```shell
java -jar target/certValidator-1.0-SNAPSHOT-jar-with-dependencies.jar --sslHost localhost --sslPort 443 --keyStorePath keystore.jks --keyStorePassword password --trustStorePath truststore.jks --trustStorePassword password --mTLS true --protocol TLSv1.2 --cipherCheck true --listCiphers false
```


### Configuration Parameters

The application uses several configuration parameters for SSL/TLS communication. Below is a brief description of each, along with their default values:

- `sslHost`: The hostname or IP address for SSL/TLS communication. 
- `sslPort`: The port on which to establish SSL/TLS connections. 
- `keyStorePath`: Path to the keystore file containing the server's private key and certificate. 
- `keyStorePassword`: Password to access the keystore. 
- `mTLS`: Indicates whether mutual TLS is enabled. When enabled, both client and server authenticate each other. Default is `false`.
- `trustStorePath`: Path to the truststore file containing certificates trusted by the server. Default for client-side configuration. Default trusted certs are loaded from jdk cacerts.
- `trustStorePassword`: Password to access the truststore.
- `protocol`: The SSL/TLS protocol version to use. Default is `TLSv1.2`.
- `cipherCheck`: Enables or disables cipher suite checks. Default is `true`.
- `listCiphers`: A comma-separated list of cipher suites to use. The default value depends on the JVM configuration and the protocol version.

### Examples

#### To Verify SSL connectivity to a ssl endpoint with default truststore
```shell
java -jar target/certValidator-1.0-SNAPSHOT-jar-with-dependencies.jar --sslHost google.com --sslPort 443
```

#### To Verify SSL connectivity to a ssl endpoint with custom truststore
```shell
java -jar target/certValidator-1.0-SNAPSHOT-jar-with-dependencies.jar --sslHost google.com --sslPort 443 --trustStorePath truststore.jks --trustStorePassword password

```

#### To Verify SSL connectivity to a ssl endpoint with mTLS
```shell
java -jar target/certValidator-1.0-SNAPSHOT-jar-with-dependencies.jar --sslHost google.com --sslPort 443  --keyStorePath keystore.jks --keyStorePassword password  --trustStorePath truststore.jks --trustStorePassword password --mTLS true 
```

#### To Verify SSL connectivity to a ssl endpoint with custom truststore and also validate ciphers
```shell
java -jar target/certValidator-1.0-SNAPSHOT-jar-with-dependencies.jar --sslHost google.com --sslPort 443 --trustStorePath truststore.jks --trustStorePassword password --cipherCheck true 
```

#### To Verify SSL connectivity to a ssl endpoint with mTLS and also validate ciphers
```shell
java -jar target/certValidator-1.0-SNAPSHOT-jar-with-dependencies.jar --sslHost google.com --sslPort 443  --keyStorePath keystore.jks --keyStorePassword password  --trustStorePath truststore.jks --trustStorePassword password --mTLS true --cipherCheck true 
```

#### To list ciphers supported on local node
When using `--listCiphers true` all other options will be ignored
```shell
java -jar target/certValidator-1.0-SNAPSHOT-jar-with-dependencies.jar --listCiphers true
```

### Important Notes

- Ensure that the `keyStorePath` and `trustStorePath` are correctly set to point to your keystore and truststore files, respectively.
- The `keyStorePassword` and `trustStorePassword` should be kept secure and not shared.
- The `protocol` should be chosen based on the security requirements and compatibility of the systems involved in the communication. Valid values are `TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`
- If `mTLS` is enabled, both the client and server need to have their keystores and truststores properly configured for mutual authentication.
- The `listCiphers` parameter lists all the ciphers. Please note when `--listCiphers true` is set, it will skip cert validation. Use this option when only listing the ciphers. This option is helpful when validating ciphers on the server side if cert validation was failing due to cipher mismatch issues. 
