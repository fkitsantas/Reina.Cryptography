![Reina Cryptography Library](/Resources/Reina-Cryptography-Preview.jpg)
[![Build and Release](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/build-and-release.yml/badge.svg)](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/build-and-release.yml)[![Dependencies Audit](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/dependencies-audit.yml/badge.svg)](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/dependencies-audit.yml)[![Generate and Deploy Documentation](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/generate-and-deploy-documentation.yml/badge.svg)](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/generate-and-deploy-documentation.yml)
## Project Overview
Reina Cryptography is a state-of-the-art class library for .NET and .NET Framework, meticulously designed to provide advanced Cascading Triple-Layered Encryption and Decryption capabilities, along with internal key management. Focusing on security and ease of use, the library provides seamless integration with Azure Key Vault. During encryption or decryption processes, this integration automatically fetches the 256-bit encryption key(s) stored under the keyname(s) specified by the developer for Encryption/Decryption. If such key(s) do not exist, the library creates new unique 256-bit encryption key(s) and stores them under the specified keyname(s) on Azure Key Vault for future use.

## Table of Contents

1. **Introduction**
   - Core Features and Capabilities
   - Target Audience and Application Scenarios

2. **System Requirements and Dependencies**
   - Software Requirements
   - External Dependencies and Integration Points

3. **Installation Guide**
   - Step-by-Step Installation Process
   - Configuration and Setup

4. **Detailed Usage Guide**
   - Functionality Overview
     - Encryption Process Explained
     - Decryption Process Explained
   - API Reference
     - `Encrypt` Method: Detailed Description and Parameters
     - `Decrypt` Method: Detailed Description and Parameters
   - Code Samples and Best Practices

5. **Integration with Azure Key Vault**
   - Configuring Azure Key Vault
   - Managing Encryption Keys

6. **Troubleshooting and Support**
   - Common Issues and Resolutions
   - Getting Help and Support Resources

7. **Contributing to Reina.Cryptography**
   - Contribution Guidelines
   - Community and Development Process

8. **License and Legal Information**
   - Licensing Details
   - Acknowledgments and Third-Party Licenses
