#!/usr/bin/env python3
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
import re
from dataclasses import dataclass
from typing import List, Dict, Any
import requests
from azure.identity import InteractiveBrowserCredential
from colorama import init, Fore, Style

# Configure logging to only show critical errors
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger(__name__)

# Lists for additional security checks
TRAITORWARE_APPS = [
    "em client",
    "perfectdata software",
    "newsletter software supermailer",
    "cloudsponge",
    "rclone"
]

SUSPICIOUS_REPLY_URL_PATTERN = re.compile(r"^http://localhost:\d+/access/?$")

@dataclass
class AuditRule:
    name: str
    description: str
    severity: str
    check_function: callable

class AzureAppAuditor:
    def __init__(self):
        """Initialize the auditor with a clean state"""
        self.cleanup()

    def cleanup(self):
        """Clean up credentials and session data"""
        self.credential = None
        self.access_token = None
        self.tenant_name = None
        self.scope = "https://graph.microsoft.com/.default"
        self.client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office client ID
        self.token_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
        self.device_code_url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode"
        self.audit_rules = self._initialize_audit_rules()

    def _initialize_audit_rules(self) -> List[AuditRule]:
        return [
            AuditRule(
                name="Advanced Suspicious Names",
                description="Applications with complex suspicious naming patterns",
                severity="HIGH",
                check_function=self._check_advanced_suspicious_names
            ),
            AuditRule(
                name="Excessive Permissions",
                description="Applications with high-privilege permissions",
                severity="CRITICAL",
                check_function=self._check_excessive_permissions
            ),
            AuditRule(
                name="Outdated Credentials",
                description="Applications with expired or soon-to-expire credentials",
                severity="MEDIUM",
                check_function=self._check_outdated_credentials
            ),
            AuditRule(
                name="Suspicious Redirect URIs",
                description="Applications with potentially malicious redirect URIs",
                severity="HIGH",
                check_function=self._check_suspicious_redirects
            )
        ]

    def _check_advanced_suspicious_names(self, app: Dict[str, Any]) -> List[str]:
        """
        Comprehensive check for suspicious application names
        Checks include:
        - Non-alphanumeric character names
        - User-named apps
        - Test/variant apps
        - Traitorware apps
        """
        findings = []
        app_name = app.get('displayName', '').lower()
        
        # 1. Apps with non-alphanumeric characters
        if re.search(r'[^a-z0-9\s-]', app_name):
            findings.append("App name contains non-alphanumeric characters")
        
        # 2. Check if app name matches user name 
        # Note: This would require additional user information retrieval
        try:
            # Attempt to get associated user information (if available)
            owners = self._get_app_owners(app.get('id'))
            for owner in owners:
                owner_name = owner.get('displayName', '').lower()
                if owner_name in app_name or app_name in owner_name:
                    findings.append(f"App name potentially matches user name: {owner_name}")
        except Exception:
            pass  # Silently handle if owner retrieval fails
        
        # 3. Test app variants
        test_patterns = [
            r'^test$',
            r'^test\s*app$',
            r'^\s*test\s*',
            r'test\s*application',
            r'test\s*[0-9]+'
        ]
        
        for pattern in test_patterns:
            if re.search(pattern, app_name):
                findings.append(f"Possible test app name detected: {pattern}")
        
        # 4. Traitorware app names
        for traitor_app in TRAITORWARE_APPS:
            if traitor_app.lower() in app_name:
                findings.append(f"Traitorware app name detected: {traitor_app}")
        
        # 5. Suspicious reply URLs check (integrate with _check_suspicious_redirects)
        reply_urls = app.get('web', {}).get('redirectUris', [])
        suspicious_reply_urls = [
            url for url in reply_urls 
            if SUSPICIOUS_REPLY_URL_PATTERN.match(url)
        ]
        
        if suspicious_reply_urls:
            findings.append(f"Suspicious reply URLs detected: {suspicious_reply_urls}")
        
        return findings

    def _get_app_owners(self, app_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve owners for a specific application
        Placeholder method that can be expanded with actual Graph API call
        """
        try:
            owners_endpoint = f'applications/{app_id}/owners'
            owners = self._make_graph_request(owners_endpoint)
            return owners.get('value', [])
        except Exception:
            return []

    def authenticate_device_code(self):
        """Authenticate using device code flow"""
        try:
            print(f"\n{Fore.YELLOW}[*] Initiating device code authentication...{Style.RESET_ALL}")
            
            # Get device code
            device_code_response = requests.post(self.device_code_url, data={
                'client_id': self.client_id,
                'scope': self.scope
            })
            device_code_data = device_code_response.json()
            
            if 'error' in device_code_data:
                print(f"{Fore.RED}[!] Failed to get device code: {device_code_data['error_description']}{Style.RESET_ALL}")
                return False
            
            # Display instructions to user
            print(f"\n{Fore.CYAN}To sign in, use a web browser to open the page {Fore.YELLOW}https://microsoft.com/devicelogin{Style.RESET_ALL}")
            print(f"{Fore.CYAN}and enter the code {Fore.YELLOW}{device_code_data['user_code']}{Fore.CYAN} to authenticate.{Style.RESET_ALL}")
            
            # Poll for token
            token_request_data = {
                'client_id': self.client_id,
                'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                'device_code': device_code_data['device_code']
            }
            
            interval = device_code_data.get('interval', 5)
            expires_in = device_code_data.get('expires_in', 900)
            start_time = datetime.now()
            
            while (datetime.now() - start_time).total_seconds() < expires_in:
                token_response = requests.post(self.token_url, data=token_request_data)
                token_data = token_response.json()
                
                if 'error' not in token_data:
                    self.access_token = token_data['access_token']
                    
                    # Get tenant details
                    tenant_info = self._make_graph_request('organization')
                    self.tenant_name = tenant_info.get('value', [{}])[0].get('displayName', 'unknown-tenant')
                    
                    print(f"\n{Fore.GREEN}[+] Successfully authenticated to tenant: {self.tenant_name}{Style.RESET_ALL}")
                    return True
                
                if token_data['error'] != 'authorization_pending':
                    print(f"\n{Fore.RED}[!] Authentication failed: {token_data.get('error_description', 'Unknown error')}{Style.RESET_ALL}")
                    return False
                
                print(f"\r{Fore.YELLOW}[*] Waiting for device code authentication... {Style.RESET_ALL}", end='')
                time.sleep(interval)
            
            print(f"\n{Fore.RED}[!] Authentication timed out{Style.RESET_ALL}")
            return False
            
        except Exception as e:
            print(f"\n{Fore.RED}[!] Device code authentication failed: {str(e)}{Style.RESET_ALL}")
            return False

    def authenticate_browser(self):
        """Authenticate using interactive browser login"""
        try:
            print(f"\n{Fore.YELLOW}[*] Opening browser for authentication...{Style.RESET_ALL}")
            self.credential = InteractiveBrowserCredential()
            token = self.credential.get_token(self.scope)
            self.access_token = token.token
            
            # Get tenant details
            tenant_info = self._make_graph_request('organization')
            self.tenant_name = tenant_info.get('value', [{}])[0].get('displayName', 'unknown-tenant')
            
            print(f"{Fore.GREEN}[+] Successfully authenticated to tenant: {self.tenant_name}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Browser authentication failed: {str(e)}{Style.RESET_ALL}")
            return False

    def authenticate(self):
        """Handle authentication method selection and process"""
        # Clear any existing credentials
        self.cleanup()
        
        while True:
            print(f"\n{Fore.CYAN}=== Authentication Method ==={Style.RESET_ALL}")
            print("1. Device Code Authentication (No browser required)")
            print("2. Browser Authentication")
            print("3. Return to Main Menu")
            
            choice = input(f"\n{Fore.YELLOW}Select authentication method (1-3): {Style.RESET_ALL}")
            
            if choice == '1':
                return self.authenticate_device_code()
            elif choice == '2':
                return self.authenticate_browser()
            elif choice == '3':
                return False
            else:
                print(f"\n{Fore.RED}[!] Invalid option. Please try again.{Style.RESET_ALL}")

    def _make_graph_request(self, endpoint: str) -> Dict[str, Any]:
        """Make authenticated request to Microsoft Graph API"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        try:
            response = requests.get(
                f'https://graph.microsoft.com/v1.0/{endpoint}',
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"{Fore.RED}[!] API request failed: {str(e)}{Style.RESET_ALL}")
            return {}

    def _check_excessive_permissions(self, app: Dict[str, Any]) -> List[str]:
        high_risk_permissions = [
            'Directory.ReadWrite.All',
            'User.ReadWrite.All',
            'Mail.ReadWrite',
            'Files.ReadWrite.All'
        ]
        
        findings = []
        required_resource_access = app.get('requiredResourceAccess', [])
        
        for resource in required_resource_access:
            for scope in resource.get('resourceAccess', []):
                if scope.get('id') in high_risk_permissions:
                    findings.append(f"High-risk permission detected: {scope.get('id')}")
        
        return findings

    def _check_outdated_credentials(self, app: Dict[str, Any]) -> List[str]:
        findings = []
        now = datetime.now(timezone.utc)
        warning_threshold = now + timedelta(days=30)
        
        for key_credential in app.get('keyCredentials', []):
            try:
                end_date_str = key_credential.get('endDateTime')
                if not end_date_str:
                    continue
                    
                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
                
                if end_date < now:
                    findings.append(f"Expired credential found: {key_credential.get('keyId')}")
                elif end_date < warning_threshold:
                    findings.append(f"Credential near expiration: {key_credential.get('keyId')}")
            except (ValueError, AttributeError):
                continue
                
        return findings

    def _check_suspicious_redirects(self, app: Dict[str, Any]) -> List[str]:
        suspicious_patterns = [
            r'localhost',
            r'ngrok\.io',
            r'0\.0\.0\.0',
            r'file://',
            r'data://'
        ]
        
        findings = []
        redirect_uris = app.get('web', {}).get('redirectUris', [])
        
        for uri in redirect_uris:
            for pattern in suspicious_patterns:
                if re.search(pattern, uri.lower()):
                    findings.append(f"Suspicious redirect URI detected: {uri}")
                    break
        
        return findings

    def audit_applications(self) -> Dict[str, List[Dict[str, Any]]]:
        """Perform comprehensive audit of applications"""
        if not self.access_token:
            print(f"{Fore.RED}[!] Not authenticated. Please authenticate first.{Style.RESET_ALL}")
            return {}

        print(f"\n{Fore.YELLOW}[*] Scanning applications...{Style.RESET_ALL}")
        applications = self._make_graph_request('applications')
        audit_results = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': []
        }

        total_apps = len(applications.get('value', []))
        print(f"{Fore.CYAN}[*] Found {total_apps} applications to analyze{Style.RESET_ALL}")

        for i, app in enumerate(applications.get('value', []), 1):
            print(f"\r{Fore.YELLOW}[*] Analyzing application {i}/{total_apps}...{Style.RESET_ALL}", end='')
            
            app_findings = {
                'appId': app.get('appId'),
                'displayName': app.get('displayName'),
                'findings': []
            }

            for rule in self.audit_rules:
                findings = rule.check_function(app)
                if findings:
                    app_findings['findings'].extend([{
                        'rule': rule.name,
                        'severity': rule.severity,
                        'details': finding
                    } for finding in findings])

            if app_findings['findings']:
                max_severity = max(f['severity'] for f in app_findings['findings'])
                if max_severity == 'CRITICAL':
                    audit_results['high_risk'].append(app_findings)
                elif max_severity == 'HIGH':
                    audit_results['medium_risk'].append(app_findings)
                else:
                    audit_results['low_risk'].append(app_findings)

        print()  # New line after progress
        return audit_results

    def print_detailed_results(self, results: Dict[str, List[Dict[str, Any]]]):
        """Print detailed findings to terminal"""
        print(f"\n{Fore.CYAN}=== Detailed Findings ==={Style.RESET_ALL}")
        
        for risk_level, apps in results.items():
            if apps:
                color = Fore.RED if risk_level == 'high_risk' else Fore.YELLOW if risk_level == 'medium_risk' else Fore.GREEN
                print(f"\n{color}{risk_level.upper().replace('_', ' ')}{Style.RESET_ALL}")
                
                for app in apps:
                    print(f"\n{color}Application: {app['displayName']}{Style.RESET_ALL}")
                    print(f"AppID: {app['appId']}")
                    for finding in app['findings']:
                        print(f"  • {finding['rule']}: {finding['details']}")

    def export_results(self, results: Dict[str, List[Dict[str, Any]]]):
        """Export audit results to JSON file in reports directory"""
        try:
            # Create reports directory if it doesn't exist
            os.makedirs('reports', exist_ok=True)
            
            # Generate filename with tenant name and timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/{self.tenant_name}_{timestamp}_audit.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            print(f"\n{Fore.GREEN}[+] Results exported to {filename}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"\n{Fore.RED}[!] Failed to export results: {str(e)}{Style.RESET_ALL}")


def print_documentation():
    """Print comprehensive documentation about the Azure Application Security Auditor"""
    print(f"\n{Fore.CYAN}=== Azure Application Security Auditor - Documentation ==={Style.RESET_ALL}")
    print("\n" + "="*60)
    print(f"{Fore.GREEN}Purpose:{Style.RESET_ALL}")
    print("This script provides a comprehensive security audit of Azure AD applications")
    print("by analyzing registered applications for potential security risks.")
    
    print(f"\n{Fore.GREEN}Authentication Methods:{Style.RESET_ALL}")
    print("1. Device Code Authentication:")
    print("   - No browser required")
    print("   - Generates a device code for web-based authentication")
    print("   - Secure method for accessing Microsoft Graph API")
    
    print("\n2. Browser Authentication:")
    print("   - Opens interactive browser login")
    print("   - Uses Azure Identity library for secure authentication")
    
    print(f"\n{Fore.GREEN}Security Audit Checks:{Style.RESET_ALL}")
    print("1. Advanced Suspicious Names:")
    print("   - Detects applications with non-alphanumeric character names")
    print("   - Identifies apps potentially named after users")
    print("   - Flags test/development application variants")
    print("   - Checks against a predefined list of 'traitorware' applications")
    
    print("\n2. Excessive Permissions:")
    print("   - Identifies applications with high-risk permissions such as:")
    print("     * Directory.ReadWrite.All")
    print("     * User.ReadWrite.All")
    print("     * Mail.ReadWrite")
    print("     * Files.ReadWrite.All")
    
    print("\n3. Outdated Credentials:")
    print("   - Checks for expired credentials")
    print("   - Warns about credentials approaching expiration (within 30 days)")
    
    print("\n4. Suspicious Redirect URIs:")
    print("   - Detects potentially malicious redirect URLs")
    print("   - Flags URLs with suspicious patterns like:")
    print("     * localhost")
    print("     * ngrok.io")
    print("     * 0.0.0.0")
    print("     * file:// or data:// protocols")
    
    print(f"\n{Fore.GREEN}Risk Categorization:{Style.RESET_ALL}")
    print("- High Risk: Critical security concerns")
    print("- Medium Risk: Significant potential security issues")
    print("- Low Risk: Minor or potential security observations")
    
    print(f"\n{Fore.GREEN}Output:{Style.RESET_ALL}")
    print("- Detailed console output")
    print("- JSON export of audit results in 'reports' directory")
    
    print(f"\n{Fore.YELLOW}DISCLAIMER:{Style.RESET_ALL}")
    print("\nThis tool is a PROOF-OF-CONCEPT and should not be considered")
    print("a complete or definitive security solution.")
    
    input(f"\n{Fore.CYAN}Press Enter to return to main menu...{Style.RESET_ALL}")

def print_menu():
    """Print the main menu"""
    print(f"\n{Fore.CYAN}=== Azure Application Security Auditor ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}========================================{Style.RESET_ALL}")
    print(f"\n1. Run Azure Tenant Audit")
    print(f"2. View Documentation")
    print(f"3. Exit")
    return input(f"\n{Fore.YELLOW}Select an option (1-3): {Style.RESET_ALL}")


def main():
    init()  # Initialize colorama
    
    while True:
        choice = print_menu()
        
        if choice == '1':
            auditor = AzureAppAuditor()  # Create new instance for each audit
            
            if not auditor.authenticate():
                print(f"\n{Fore.RED}[!] Authentication failed. Returning to menu.{Style.RESET_ALL}")
                continue
                
            results = auditor.audit_applications()
            
            if results:  # Only show results if we got data back
                # Print summary
                print(f"\n{Fore.CYAN}=== Audit Summary ==={Style.RESET_ALL}")
                print(f"{Fore.RED}High Risk Applications: {len(results['high_risk'])}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Medium Risk Applications: {len(results['medium_risk'])}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Low Risk Applications: {len(results['low_risk'])}{Style.RESET_ALL}")
                
                # Print detailed findings
                auditor.print_detailed_results(results)
                
                # Export results
                auditor.export_results(results)
            
            # Cleanup before returning to menu
            print(f"\n{Fore.YELLOW}[*] Cleaning up session...{Style.RESET_ALL}")
            auditor.cleanup()
            print(f"{Fore.GREEN}[+] Successfully disconnected from tenant{Style.RESET_ALL}")
            
            input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")
        
        elif choice == '2':
            print_documentation()
        
        elif choice == '3':
            print(f"\n{Fore.GREEN}[+] Goodbye!{Style.RESET_ALL}")
            break
            
        else:
            print(f"\n{Fore.RED}[!] Invalid option. Please try again.{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Script interrupted by user. Exiting...{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")