# Azure Application Security Auditor
The Azure Application Security Auditor is a Python-based tool designed to perform comprehensive security assessments of applications registered in Azure Active Directory (Azure AD). This script helps security professionals and administrators identify potential security risks in their Azure AD application registrations.

## Features
### Security Audit Checks
The tool performs four primary security checks:
1. Advanced Suspicious Names
    - Detects applications with potentially suspicious naming patterns
    - Identifies apps named after users
    - Flags test/development application variants
    - Checks against a predefined list of 'traitorware' applications
2. Excessive Permissions
    - Identifies applications with high-risk permissions, including:
        - Directory.ReadWrite.All
        - User.ReadWrite.All
        - Mail.ReadWrite
        - Files.ReadWrite.All

3. Outdated Credentials
    - Checks for expired credentials
    - Warns about credentials approaching expiration (within 30 days)
  
4. Suspicious Redirect URIs
    - Detects potentially malicious redirect URLs
    - Flags URLs with suspicious patterns like:
        - localhost
        - ngrok.io
        - 0.0.0.0
        - file:// or data:// protocols
### Risk Categorization
Applications are categorized into three risk levels:
    - High Risk: Critical security concerns
    - Medium Risk: Significant potential security issues
    - Low Risk: Minor or potential security observations
    
### Prerequisites
    - Python 3.7+
    - Required Python packages:
        - azure-identity
        - requests
        - colorama

### Authentication Methods
The script supports two authentication methods:

Device Code Authentication

No browser required
Generates a device code for web-based authentication
Secure method for accessing Microsoft Graph API


### Usage
Run the script: _python azure_app_auditor.py_

Main Menu Options
1. Run Azure Tenant Audit
    - Authenticate to your Azure AD tenant
    - Scan and analyze registered applications
    - View detailed findings
    - Export results to JSON
2. View Documentation
    - Display tool documentation
3. Exit
    - Close the application (derr)

### Security Considerations
🚨 IMPORTANT: This is a PROOF-OF-CONCEPT tool and should not be considered a complete or definitive security solution. Always complement automated tools with manual security reviews.

### License
Distributed under the MIT License. See LICENSE for more information.
