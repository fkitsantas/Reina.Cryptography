![Reina Cryptography Library](/Resources/Reina-Cryptography-Preview.jpg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/license/mit/) &nbsp; [![Build and Release](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/build-and-release.yml/badge.svg)](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/build-and-release.yml) &nbsp; [![Generate and Deploy Documentation](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/generate-and-deploy-documentation.yml/badge.svg)](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/generate-and-deploy-documentation.yml)

## Project Overview
Reina Cryptography is a state-of-the-art class library for .NET and .NET Framework, meticulously designed to provide advanced Cascading Triple-Layered Encryption and Decryption capabilities, along with internal key management. Focusing on security and ease of use, the library provides seamless integration with Azure Key Vault. During encryption or decryption processes, this integration automatically fetches the 256-bit encryption key(s) stored under the keyname(s) specified by the developer for Encryption/Decryption. If such key(s) do not exist, the library creates new unique 256-bit encryption key(s) and stores them under the specified keyname(s) on Azure Key Vault for future use.

## Table of Contents
1. [**Introduction**](#introduction)
   - [Core Features and Capabilities](#core-features-and-capabilities)
   - [Target Audience and Application Scenarios](#target-audience-and-application-scenarios)
2. [**Requirements and Dependencies**](#system-requirements-and-dependencies)
   - [Software Requirements](#software-requirements)
   - [External Dependencies](#external-dependencies)
3. [**Detailed Usage Guide**](#detailed-usage-guide)
   - [Functionality Overview](#functionality-overview)
     - [Encryption Process Explained](#encryption-process-explained)
     - [Decryption Process Explained](#decryption-process-explained)
   - [Integration with Azure Key Vault](#integration-with-azure-key-vault)
      - [Configuration - Azure Key Vault Credentials](#configuration---azure-key-vault-credentials)
   - [API Reference](#api-reference)
     - [`Configuration` Method: Detailed Description and Parameters](#configuration-method-detailed-description-and-parameters)
     - [`Encrypt` Method: Detailed Description and Parameters](#encrypt-method-detailed-description-and-parameters)
     - [`Decrypt` Method: Detailed Description and Parameters](#decrypt-method-detailed-description-and-parameters)
   - [Code Samples and Best Practices](#code-samples-and-best-practices)
4. [**Project Design**](#project-design)
   - [Architecture Overview](#architecture-overview)
   - [Library Structure](#library-structure)
   - [Streamlined CI/CD with GitHub Actions](#streamlined-cicd-with-github-actions)
      - [Dependabot](#dependabot)
      - [Build and Release](#build-and-release)
      - [Generate and Deploy Documentation](#generate-and-deploy-documentation)
5. [**Security Considerations**](#security-considerations)
   - [Security Enhancement with a .NET Obfuscator](#security-enhancement-with-a-net-obfuscator)
6. [**Troubleshooting and Support**](#troubleshooting-and-support)
   - [Common Issues and Resolutions](#common-issues-and-resolutions)
   - [Getting Help and Support Resources](#getting-help-and-support-resources)
7. [**Contributing to Reina.Cryptography**](#contributing-to-reina-cryptography)
   - [Contribution Guidelines](#contribution-guidelines)
   - [Community and Development Process](#community-and-development-process)
8. [**License and Legal Information**](#license-and-legal-information)
   - [Licensing Details](#licensing-details)
   - [Acknowledgments and Third-Party Licenses](#acknowledgments-and-third-party-licenses)
9. [**About Reina.Cryptography**](#about-reinacryptography)
   - [Author](#author)
---

## Introduction

Reina Cryptography is designed to integrate effortlessly with Azure Key Vault, providing a robust and secure management system for 256-bit encryption keys, enabling developers to perform extremely complex encryption and decryption tasks with ease.

### Core Features and Capabilities

 The core features that define the essence of this library:
- **Seamless Azure Key Vault Integration**: The library integrates flawlessly with Azure Key Vault, ensuring secure and efficient management of 256-bit encryption keys. This integration guarantees that cryptographic keys are not only safeguarded but also readily available for encryption tasks. The developer doesn't have to worry about store/retrieve of these keys as the Library handles that during encryption and decryption automatically.
  
- **Flexible Key Management Options**: The library provides the flexibility to generate and utilize distinct 256-bit keys for each encryption algorithm or to employ a single key across multiple algorithms. This flexibility allows developers to choose the level of granularity in key management that best suits their application's needs. By leveraging Azure Key Vault, Reina Cryptography ensures that these cryptographic keys will remain safe on the cloud for future use, instead of being hardcoded, thereby enhancing security and reducing the potential for key compromise.
  
- **Triple-Layered Cascading Encryption Technique**: At the heart of Reina Cryptography is the Cascading Encryption Technique, which empowers developers to layer encryption through a sequence of Twofish, Serpent, and AES algorithms. This methodical layering is more than just a security feature; it's a commitment to data integrity and confidentiality. Even in the event of a breach in one encryption layer, the remaining layers maintain their defensive posture, safeguarding the encrypted data.
  
- **Unique Initialization Vector (IV) for Each Operation**: Each encryption operation within the library is complemented by a securely generated, unique Initialization Vector (IV). These IVs are not merely appended but are intricately woven into the ciphertext, bolstering the encryption against pattern analysis and brute-force attacks. This strategic approach to encryption ensures that each piece of data remains an enigma, challenging even the most advanced decryption attempts.

Building on these core features, Reina Cryptography offers a comprehensive solution for developers seeking a robust and versatile encryption toolkit.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Target Audience and Application Scenarios

Reina Cryptography is designed to cater to a diverse range of users and application scenarios, making it a versatile tool in the realm of encryption and security.

#### Target Audiences:
- **Software Development Companies**: Ideal for companies looking to enhance the security of their applications, Reina Cryptography can be integrated into their development process. Companies can hardcode their Azure Key Vault credentials in the `Config.cs` file, obfuscate the produced .dll, and distribute it to their development teams. This approach allows developers to leverage the company's Azure Key Vault for encryption and decryption tasks without direct access to the sensitive credentials, ensuring a secure and centralized key management system.

- **Individual Developers**: The library is also well-suited for individual developers working on .NET or .NET Framework applications who require robust encryption capabilities. Whether for personal projects or professional development, Reina Cryptography offers an easy way to integrate Azure Key Vault and implement advanced encryption techniques.

- **Enterprise Security Solutions**: Enterprises seeking to bolster their data security can utilize Reina Cryptography to protect sensitive information. The library's advanced encryption methods are ideal for securing data in transit and at rest, making it a valuable tool for enterprise security strategies.

#### Application Scenarios:
- **Cloud-Based Applications**: For applications deployed in cloud environments, Reina Cryptography provides an additional layer of security. Its integration with Azure Key Vault makes it particularly suitable for applications hosted on Azure, ensuring that encryption keys are managed securely in the cloud.

- **Financial Technology (FinTech) Applications**: In the FinTech sector, where data security is paramount, Reina Cryptography can be used to secure financial transactions and sensitive customer data. Its robust encryption capabilities ensure that financial data remains confidential and secure.

- **Healthcare Applications**: Healthcare applications dealing with sensitive patient data can benefit from the high level of security offered by Reina Cryptography. The library ensures that patient information is encrypted and stored securely, complying with regulatory standards like HIPAA.

- **E-Commerce Platforms**: E-commerce sites handling customer data and transactions can use Reina Cryptography to secure customer information, payment details, and transaction records, providing customers with confidence in the platform's security measures.

- **Government and Public Sector**: Ideal for government agencies requiring secure data storage, especially in handling sensitive citizen data.

In summary, Reina Cryptography is a versatile library that can be employed in various scenarios where data security is crucial. Its ease of integration with Azure Key Vault and its advanced encryption capabilities make it an ideal choice for a wide range of applications, from individual developer projects to large-scale enterprise solutions.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Requirements and Dependencies

### Software Requirements

The library is designed for use with the .NET Framework and .NET platforms.

- **.NET Framework 4.8.1**: The latest major release of Microsoft's .NET Framework. [Download .NET Framework 4.8.1](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net481)

- **.NET 7**: The latest major release of Microsoft's .NET. [Download .NET 7](https://dotnet.microsoft.com/en-us/download/dotnet/7.0)
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### External Dependencies

Reina Cryptography integrates with external libraries to provide its advanced features. The following dependencies are used internally for the library's functionality:
- **Azure SDK Packages**:
  - `Azure.Core`: Provides shared components for Azure client libraries.
  - `Azure.Identity`: Enables Azure Active Directory token authentication.
  - `Azure.Security.KeyVault.Keys`: Manages keys and related cryptographic operations in Azure Key Vault.
  - `Azure.Security.KeyVault.Secrets`: Handles secrets and secure storage in Azure Key Vault.
- **BouncyCastle Cryptography**: A comprehensive cryptography library providing a range of encryption algorithms.
- **Fody** and **Costura.Fody**: Used for embedding dependencies into the library assembly, ensuring a single, self-contained DLL.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Detailed Usage Guide

### Functionality Overview

#### Encryption Process Explained

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

#### Decryption Process Explained

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Integration with Azure Key Vault

#### Configuration - Azure Key Vault Credentials

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### API Reference

#### `Configuration` Method: Detailed Description and Parameters

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

#### `Encrypt` Method: Detailed Description and Parameters

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

#### `Decrypt` Method: Detailed Description and Parameters

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Code Samples and Best Practices

asdasdaasd
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Project Design

### Architecture Overview

The key architectural components are as follows:
1. **Interface Layer**: Defines the contract for each module, ensuring a clear separation of concerns and promoting a plug-and-play approach.
2. **Implementation Layer**: Contains concrete implementations of the interfaces, providing the core functionalities of the library. This layer ensures that each module can be extended or replaced without affecting other parts of the system.
3. **Integration with Azure Key Vault**: The key management module integrates with Azure Key Vault, ensuring that encryption keys are securely managed and stored.
4. **Exception Handling**: Comprehensive exception handling ensures that any issues, whether related to configuration, encryption, or key management, are clearly communicated to the developer.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Library Structure

- **Configuration**: Contains the `Config` class which manages the configuration settings for accessing Azure Key Vault.
- **Decryption**: Contains the `DataDecryptor` class responsible for decrypting data.
- **Encryption**: Contains the `DataEncryptor` class responsible for encrypting data.
- **Interfaces**: Defines the interfaces for configuration, encryption, decryption, and key management.
- **Key Management**: Contains the `AzureKVKeyManager` class which integrates with Azure Key Vault for key management.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Streamlined CI/CD with GitHub Actions

Continuous Integration and Continuous Deployment (CI/CD) are fundamental practices in modern software development, aimed at enhancing code quality and streamlining the release process. Reina Cryptography leverages GitHub Actions to automate the CI/CD pipeline. This automation ensures that every code push is built, tested (ToDo), and released automatically. Additionally, the documentation is dynamically generated and deployed, keeping the project's documentation up-to-date with the latest changes. Below are the badges representing the status of the CI/CD pipelines:

- **Build and Release**: This badge reflects the current status of the build and release pipeline, ensuring that every change in the main branch is automatically built and ready for release.  
  [![Build and Release](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/build-and-release.yml/badge.svg)](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/build-and-release.yml)

- **Generate and Deploy Documentation**: This badge indicates the status of the documentation generation and deployment process. It ensures that the documentation is always synchronized with the latest version of the code.  
  [![Generate and Deploy Documentation](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/generate-and-deploy-documentation.yml/badge.svg)](https://github.com/fkitsantas/Reina.Cryptography/actions/workflows/generate-and-deploy-documentation.yml)


#### Dependabot

Reina Cryptography leverages GitHub's Dependabot to ensure all dependencies are up-to-date. Dependabot checks daily for updates in project dependencies and automatically creates pull requests to update the `PackageReference` versions in the project file. This proactive approach ensures that the library is always using the latest, most secure versions of its dependencies, reducing the risk of vulnerabilities.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

#### Build and Release

The ["Build and Release" workflow](https://github.com/fkitsantas/Reina.Cryptography/blob/main/.github/workflows/build-and-release.yml) in GitHub Actions is a crucial part of Reina Cryptography's CI/CD pipeline. This workflow is triggered on every push to the main branch, excluding changes to workflow files, resources, and the README.md file. The steps involved in this workflow are:

1. **Check out code**: The latest version of the codebase is checked out for building and releasing.

2. **Get the last commit message**: This step captures the last commit message for use in the release notes.

3. **Calculate version number**: The workflow calculates a new version number based on the number of commits. This ensures a unique version for each build, facilitating traceability and version management.

4. **Update project version**: The calculated version number is then used to update the project file (`Reina.Cryptography.csproj`).

5. **Build Project**: The project is built for both .NET Framework 4.8.1 and .NET 7, ensuring compatibility across different environments.

6. **Create Release**: A new GitHub release is created with the calculated version number, including the last commit message as the release note.

7. **Upload .dll files**: The built DLL files for both .NET Framework 4.8.1 and .NET 7 are uploaded as assets to the GitHub release, making them available for download.

This workflow automates the process of building, versioning, and releasing the library, ensuring a consistent and reliable delivery process.

<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

#### Generate and Deploy Documentation

The ["Generate and Deploy Documentation" workflow](https://github.com/fkitsantas/Reina.Cryptography/blob/main/.github/workflows/generate-and-deploy-documentation.yml) is another integral part of the CI/CD pipeline. This workflow is responsible for automatically generating and deploying the project's documentation. The steps include:

1. **Checkout Repository**: The latest version of the repository is checked out.

2. **Install Doxygen**: Doxygen, a documentation generation tool, is installed on the runner.

3. **Generate Documentation**: Doxygen reads the configured `Doxyfile` and generates documentation from the codebase.

4. **Deploy to GitHub Pages**: The generated documentation is then deployed to GitHub Pages, making it accessible to users and contributors. This ensures that the project's documentation is always up-to-date with the latest code changes.

This workflow simplifies the process of maintaining up-to-date and accessible documentation, which is crucial for both users and contributors to understand and effectively use the library.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Security Considerations

### Security Enhancement with a .NET Obfuscator

For an added layer of security, especially when handling sensitive information like Azure Key Vault credentials in your DLL, it is highly recommended to use a .NET Obfuscator. In this context, .NET Reactor emerges as a top choice. It offers advanced protection against reverse engineering, vital to prevent unauthorized access to your Azure Key Vault credentials and the keys it safeguards.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Troubleshooting and Support

### Common Issues and Resolutions

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Getting Help and Support Resources

If you encounter any issues or have questions regarding Reina.Cryptography, please feel free to seek assistance through the Issues page.

To open an issue, please visit: [Reina.Cryptography Issues](https://github.com/fkitsantas/Reina.Cryptography/issues).
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Contributing to Reina.Cryptography

### Contribution Guidelines

Contributions to the project are warmly welcomed. If you're interested in contributing, here are some guidelines to help you get started:

1. **Fork the Repository**: Begin by forking the [Reina.Cryptography repository](https://github.com/fkitsantas/Reina.Cryptography) on GitHub.

2. **Create a Branch**: For each new feature or bug fix, create a new branch in your forked repository. This helps keep changes organized.

3. **Code Conventions**: Please follow the existing coding style and conventions. This includes proper documentation for any new code and adhering to the established architectural patterns.

4. **Testing**: Ensure that your code is thoroughly tested. Quality and reliability are paramount, and comprehensive tests help maintain these standards.

5. **Pull Requests**: Once your changes are ready, submit a pull request with a clear description of the changes and any relevant issue numbers.

6. **Code Review**: I will review your pull request. Be open to feedback and ready to make revisions if necessary.

7. **Merging**: After approval, your changes will be merged into the main branch.

Your contributions are crucial in the continuous development and improvement of Reina.Cryptography. I appreciate your efforts in making this project better for everyone.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Community and Development Process

The development of Reina.Cryptography is currently a solo endeavor, but I am hopeful that it will grow into a community-driven project. Here's how you can be part of this journey:

- **Stay Updated**: Follow the project on GitHub to stay updated with the latest developments.
- **Join Discussions**: Participate in discussions on GitHub issues and pull requests. Your insights and feedback are valuable.
- **Share Your Experiences**: If you've integrated Reina.Cryptography in your project(s), consider sharing your experiences. This helps others learn and grow.
- **Report Issues**: If you find bugs or have suggestions for improvements, please report them through GitHub issues.

Your engagement and contributions are what will shape the future of Reina.Cryptography. Together, we can build a robust, secure, and user-friendly cryptography library.
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## License and Legal Information

### Licensing Details

Reina.Cryptography is available under the MIT License, a permissive free software license. This means you are free to use, modify, distribute, and even use the library commercially, as long as you include the original copyright and license notice in any copy of the software or substantial portions of it. The full details of the MIT License can be viewed on the project's [License](LICENSE).
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Acknowledgments and Third-Party Licenses

Reina.Cryptography extends its gratitude to the Legion of the Bouncy Castle for their foundational cryptographic library. Their work has been instrumental in the development of this project. For more information about their contributions to the field of cryptography, please visit their [official website](https://www.bouncycastle.org).
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## About Reina.Cryptography

<img align="left" src="Resources/Reina-Cryptography.png" width="300px" />

*"I married a Software Engineer, who codes all day but hasn't created an app with my name"* said my wife, Reina, half-jokingly. So, here we are..

Reina.Cryptography, a top-notch Class Library for .NET & .NET Framework, dedicated to my drop-dead gorgeous and out-of-this-world amazing wife, Reina. ❤️

### Author

**Fotios Kitsantas** ([fkitsantas@icloud.com](mailto:fkitsantas@icloud.com))  
Senior Software Engineer  
📍 London, United Kingdom

For inquiries or feedback, please contact via the provided email.  
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>
