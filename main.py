import CWAPI
import json
import pandas as pd
from datetime import datetime
import getpass
import os


def GenerateFile(data):
    for app in data.get("content", []):
        operation_mode = app.get("featuresData", {}).get("wafFeatureData", {}).get("operationMode", {})
        mode = operation_mode.get("mode", "N/A")
        if mode == "FAILOVER":
            primary = operation_mode.get("failoverMode", {}).get("primaryAddress", {})
            secondary = operation_mode.get("failoverMode", {}).get("secondaryAddress", {})
            fqdn_value = f"Primary - {primary.get('addressType', 'N/A')}: {primary.get('address ', 'N/A')}\nSecondary - {secondary.get('addressType', 'N/A')}: {secondary.get('address', 'N/A')}"
        else:
            fqdn_value = "\n".join([f"{srv['addressType']}: {srv['address']}" for srv in operation_mode.get("loadBalanceMode", {}).get("serverAddresses", [])] or ["N/A"])
        

        database_items=app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("databaseProtection", {}).get("databaseProtectionList", {}).get("databaseProtectionItems", [])
        if not isinstance(database_items, list):  # If it's not a list, set a default empty list
            database_items = []
        service_data = app.get("applicationServices", [])
        
        if isinstance(service_data, list):
            service_config = "\n".join([
                f"Front Port: {service.get('frontPort', 'N/A')}, Back Port: {service.get('backPort', 'N/A')}, Protocol: {service.get('type', 'N/A')}, Enabled: {service.get('enabled', 'N/A')}"
                for service in service_data
            ] or ["N/A"])
        else:
            service_config = "N/A"

        hc_data = app.get("healthChecks", [])
        if isinstance(hc_data, list):
            hc_config = "\n".join([
                f"ID: {hc.get('id', 'N/A')}, Type: {hc.get('type', 'N/A')}, Port: {hc.get('port', 'N/A')}, Hostname: {hc.get('hostname', 'N/A')}, URL: {hc.get('url', 'N/A')}, Response_code: {hc.get('responseCode', 'N/A')}"
                for hc in hc_data
            ] or ["N/A"])
        else:
            hc_config = "N/A"

        certificate_data = app.get("certificate") or {}
        certificate_details = "\n".join([
            f"ID: {certificate_data.get('id', 'N/A')}",
            f"Protected Domains: {certificate_data.get('protectedDomains', 'N/A')}",
            f"Issuer: {certificate_data.get('issuer', 'N/A')}",
            f"Certificate Chain: {certificate_data.get('certificateChain', 'N/A')}",
            f"Key Size: {certificate_data.get('keySize', 'N/A')}",
            f"Type: {certificate_data.get('certificateType', 'N/A')}",
            f"Kind: {certificate_data.get('certificateKind', 'N/A')}",
            f"CA: {certificate_data.get('caCertificate', 'N/A')}"
        ])

        cipher_suite = app.get("applicationSecuritySettings", {}).get("cipherSuite", {})
        cipher_name = cipher_suite.get("name", "N/A")
        cipher_list = cipher_suite.get("ciphers", [])
        if not isinstance(cipher_list, list):
            cipher_list = []
        
        ciphersuite_settings = f"Name: {cipher_name}\n" + "\n".join([f"Ciphers: {cipher}" for cipher in cipher_list] or ["N/A"])

        creation_timestamp = app.get("creationDate", "N/A")
        creation_date = datetime.fromtimestamp(creation_timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_timestamp, int) else "N/A"
        row = {
            "id": app.get("id", "N/A"),
            "name": app.get("name", "N/A"),
            "deploymentStatus": app.get("deploymentStatus", "N/A"),
            "hstsEnabled": app.get("hstsEnabled", "N/A"),
            "http2Enabled": app.get("http2Enabled", "N/A"),
            "ssrfEnabled": app.get("ssrfEnabled", "N/A"),
            "awBypassEnabled": app.get("awBypassEnabled", "N/A"),
            "workflowName": app.get("workflowName", "N/A"),
            "hstsAge": app.get("hstsAge", "N/A"),
            "ipRange": ", ".join(app.get("featuresData",{}).get("wafFeatureData",{}).get("ipRange", ["N/A"])),
            "creationDate": creation_date,
            "redirect": app.get("redirect", "N/A"),
            "cdnEnabled": app.get("cdnEnabled", "N/A"),
            "mtlsEnabled": app.get("mtlsEnabled", "N/A"),
            "customDeployment": app.get("customDeployment", "N/A"),
            "Record types": "\n".join([f"{rec['type']}: {rec['value']}" for rec in app.get("featuresData", {}).get("wafFeatureData", {}).get("dns", {}).get("dnsRecords", [])] or ["N/A"]),
            "FQDNS": fqdn_value,
            "mainDomain": app.get("featuresData", {}).get("wafFeatureData", {}).get("mainDomain", {}).get("mainDomain", "N/A"),
            "DDoS protection status": app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("ddosProtection", {}).get("protectionStatus", "N/A"),
            "allowextension status": app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("allowedFileExtensionProtection", {}).get("protectionStatus", "N/A"),
            "allowextension configuration": "\n".join([f"URI: {item['uri']}, Method: {item['method']}, Acceptable: {item['acceptable']}, Regex: {item['regex']}" for item in app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("allowedFileExtensionProtection", {}).get("allowList", {}).get("allowListItems", [])] or ["N/A"]),
            "Vulnerabilities status": app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("vulnerabilityProtection", {}).get("protectionStatus", "N/A"),
            "Vulnerabilities configuration": "\n".join([f"RuleID: {item['ruleId']}, Pattern:{item['pattern']} Details:{item['details']}" for item in app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("vulnerabilityProtection", {}).get("vulnerabilityList", {}).get("vulnerabilityItems", [])] or ["N/A"]),
            "Database Status": app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("databaseProtection", {}).get("protectionStatus", "N/A"),
            "Database configuration": "\n".join([f"Page: {item.get('page', 'N/A')}\nParameter: {item.get('parameter', 'N/A')}\nRuleIDs: {', '.join(map(str, item.get('ruleIds', []) or []))}\nRegex: {item.get('regex', 'N/A')}\nDiscardAllRules: {item.get('discardAllRules', 'N/A')}" for item in database_items] or ["N/A"]),
            "Antibot Status": app.get("featuresData", {}).get("wafFeatureData", {}).get("protectionConfiguration", {}).get("antibotProtection", {}).get("protectionStatus", "N/A"),
            "ciphersuite settings": ciphersuite_settings,
            "TLS/SSL versions": "\n".join([f"{key}: {value}" for key, value in app.get("applicationSecuritySettings", {}).get("securityProtocolSet", {}).items()] or ["N/A"]),
            "Certificate details": certificate_details,
            "Certificate validFrom": datetime.fromtimestamp(certificate_data.get("validFrom", 0) / 1000).strftime('%Y-%m-%d %H:%M:%S') if isinstance(certificate_data.get("validFrom"), int) else "N/A",
            "Certificate validTo": datetime.fromtimestamp(certificate_data.get("validTo", 0) / 1000).strftime('%Y-%m-%d %H:%M:%S') if isinstance(certificate_data.get("validTo"), int) else "N/A",
            "Service information": service_config,
            "HC information": hc_config    
        }

        rows.append(row)

def main():
    cn=input("Customer name: ")
    app_name_filter = input("Enter the application name to filter (or ALL for all the apps): ")
    un=input("Enter your username: ")
    ps=getpass.getpass("Enter your password: ")
    z=CWAPI.CloudWAFAPI(username=un,password=ps)
    z.login()
    data=z.AppList()
    pages=data["totalPages"] 
    print(f"Total pages: {pages}")
    directory = "Reports"
    if not os.path.exists(directory):
        os.makedirs(directory)
    # Define the headers
    headers = [
        "name", "deploymentStatus", "mainDomain",
        "FQDNS", "creationDate", "Antibot Status","allowextension status", "allowextension configuration", "Vulnerabilities status", "Vulnerabilities configuration","Database Status", "Database configuration",
        "hstsEnabled", "http2Enabled", "ssrfEnabled", "awBypassEnabled", "workflowName",
        "hstsAge", "ipRange", "redirect", "cdnEnabled", "mtlsEnabled", "customDeployment", "Record types","id",  "DDoS protection status",
         "ciphersuite settings", "Certificate details",
        "Certificate validFrom", "Certificate validTo", "Service information","HC information", "TLS/SSL versions"
    ]
    
    found=False
    for page in range(pages):
        print(f"Retrieving data from page {page}")
        data=z.Mapper(page=page)
        last=data["last"]
        app_exists = any(app.get("name") == app_name_filter for app in data.get("content", []))
        app_found = app_exists or app_name_filter == "ALL"
        #Application filter applied or not
        if app_name_filter!="ALL" and app_found:
            filtered_content = [app for app in data.get("content", []) if app.get("name") == app_name_filter]

            # Create a new JSON structure with the filtered content
            filtered_data = {
                "number": data["number"],
                "size": data["size"],
                "totalPages": 1 if filtered_content else 0,
                "numberOfElements": len(filtered_content),
                "totalElements": len(filtered_content),
                "previousPage": False,
                "first": True,
                "nextPage": False,
                "last": True,
                "content": filtered_content
            }
            data=filtered_data
            print(f"The application {app_name_filter} has been found on page {page}")
            found=True
            GenerateFile(data)
        elif app_name_filter=="ALL":
            data=data
            GenerateFile(data)
        elif last:
            print("Error: The application doesn't exist")
            exit()   
        else:
            print(f"Application not found on page {page}")
        if found:
            break
    # Create DataFrame and save to Excel
    df = pd.DataFrame(rows, columns=headers)
    output_dir = "Reports"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"CW_ConfigMapper_{cn}.xlsx")
    df.to_excel(output_file, index=False)

    print(f"Excel file created: {output_file}")

if __name__ == "__main__": 
    rows = []
    main()



