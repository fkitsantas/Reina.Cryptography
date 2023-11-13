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

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Library Structure

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Streamlined CI/CD with GitHub Actions

#### Dependabot

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

#### Build and Release

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

#### Generate and Deploy Documentation

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Security Considerations

### Security Enhancement with a .NET Obfuscator

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Troubleshooting and Support

### Common Issues and Resolutions

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Getting Help and Support Resources

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## Contributing to Reina.Cryptography

### Contribution Guidelines

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Community and Development Process

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

## License and Legal Information

### Licensing Details

asdasda
<a href="#table-of-contents" title="Back to Top"><img align="right" src="Resources/backtotop.png" alt="Back to Top" width="35" height="35"></a>

### Acknowledgments and Third-Party Licenses

asdasda
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
