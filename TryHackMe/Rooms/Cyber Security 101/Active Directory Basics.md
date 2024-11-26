# Windows Domain and Active Directory Overview

## What is a Windows Domain?
- A **Windows domain** is a group of users and computers managed centrally by a business using a central repository called **Active Directory (AD)**.
- The server running Active Directory is known as the **Domain Controller (DC)**.

---

## Why Use a Windows Domain?

1. **Centralised Identity Management**:
   - Users and computers across the network are managed from Active Directory with minimal effort.
   - Example: A single set of credentials works on all domain-connected computers.

2. **Managing Security Policies**:
   - Security policies are configured in Active Directory and applied across the network to users and computers.
   - Example: Restricting access to the control panel or administrative privileges on machines.

---

## Real-World Examples
- **School/University Networks**:
  - Students use the same credentials on all campus machines.
  - Restrictions (e.g., no admin privileges) are applied via network-wide policies in Active Directory.

- **Workplace Networks**:
  - Employees have access to shared resources and centralised management of credentials.

---

## Why is Active Directory Important?
- Reduces the need for manual configuration of each machine.
- Enables scalable management for networks as small businesses grow.
- Ensures consistency in policies and authentication across all connected devices.

---

## Notes
- Practical exercises involving domain management and RDP login are common in IT admin tasks but are excluded from this summary.

# Active Directory Basics

## Core Service: Active Directory Domain Service (AD DS)
- **Function**: Acts as a catalogue holding information on "objects" in the network.
- **Objects** include:
  - Users
  - Machines
  - Security Groups
  - Printers, shares, and more.

---

## Key Object Types in Active Directory

### 1. **Users**
- **Definition**: Security principals authenticated by the domain and assigned privileges over network resources.
- **Types**:
  - **People**: Represent employees needing network access.
  - **Services**: Represent services like IIS or MSSQL, configured with limited privileges.
  
### 2. **Machines**
- **Definition**: Each computer joining the domain gets a machine account.
- **Characteristics**:
  - Machine accounts are security principals with limited rights in the domain.
  - Account name format: `ComputerName$` (e.g., `DC01$`).
  - Passwords: 120-character random passwords, auto-rotated.
  
### 3. **Security Groups**
- **Purpose**: Assign access rights to resources (e.g., files, printers) for multiple users/machines.
- **Features**:
  - Can include users, machines, or other groups.
  - Users inherit group privileges automatically.
- **Default Groups**:
  | Group             | Description                                                                 |
  |-------------------|-----------------------------------------------------------------------------|
  | Domain Admins     | Admin privileges for the entire domain, including DCs.                     |
  | Server Operators  | Administer DCs but cannot change admin group memberships.                  |
  | Backup Operators  | Access all files for backup purposes.                                      |
  | Account Operators | Create or modify accounts in the domain.                                   |
  | Domain Users      | All user accounts in the domain.                                           |
  | Domain Computers  | All computers in the domain.                                               |
  | Domain Controllers| All Domain Controllers in the domain.                                      |

---

## Active Directory Users and Computers (ADUC)
- **Purpose**: Manage users, groups, machines, and OUs in Active Directory.
- **Access**: Run "Active Directory Users and Computers" on the Domain Controller.
- **Objects Organized in Organizational Units (OUs)**:
  - **Definition**: Containers used to classify users/machines based on their roles.
  - Example: OUs for departments like IT, Sales, Marketing.
  - **Key Points**:
    - A user can only belong to a single OU.
    - Policies can be efficiently applied based on departmental OUs.
  - **Default Containers**:
    - **Builtin**: Default groups for Windows hosts.
    - **Computers**: Default location for newly joined machines.
    - **Domain Controllers**: Contains all DCs in the network.
    - **Users**: Default domain-wide users/groups.
    - **Managed Service Accounts**: Accounts used by domain services.

---

## Security Groups vs. Organizational Units (OUs)
| Feature              | Security Groups                                      | Organizational Units (OUs)                   |
|----------------------|------------------------------------------------------|----------------------------------------------|
| **Purpose**          | Grant permissions over resources (e.g., files).     | Apply policies to users/machines.            |
| **Membership**       | Users can belong to multiple groups.                | Users can belong to only one OU.             |
| **Example Use Case** | Grant access to a shared folder or printer.          | Define baseline policies for departments.    |

---

## Notes
- Always consider the structure of OUs and Security Groups based on the organization's requirements.
- Use ADUC to manage and modify objects efficiently.


# Windows Authentication Protocols

In Windows domains, credentials are stored in Domain Controllers. Two protocols are used for authentication:

1. **Kerberos**: Default protocol for modern Windows domains.
2. **NetNTLM**: Legacy protocol retained for compatibility.

---

## Kerberos Authentication

### Overview
- **Uses tickets** to authenticate users and grant access to services.
- Ensures credentials are not repeatedly transmitted over the network.

### Process
1. **Requesting a Ticket Granting Ticket (TGT)**:
   - User sends their username and a timestamp encrypted with a key derived from their password to the Key Distribution Center (KDC).
   - The KDC issues a **TGT** and a **Session Key**.

2. **Requesting a Ticket Granting Service (TGS)**:
   - User presents the TGT, their username, and a timestamp (encrypted with the Session Key) to the KDC, along with the Service Principal Name (SPN) of the desired service.
   - The KDC issues a **TGS** and a **Service Session Key**.

3. **Accessing the Service**:
   - The user sends the TGS to the service they want to access.
   - The service decrypts the TGS using its password hash to validate the Service Session Key and establishes a connection.

---

## NetNTLM Authentication

### Overview
- **Challenge-response mechanism** used for legacy authentication.
- Does not transmit passwords or hashes over the network.

### Process
1. Client sends an authentication request to the server.
2. The server sends a **challenge** (random number) to the client.
3. The client combines the **challenge** with their NTLM password hash to generate a **response**.
4. The server forwards the challenge and response to the Domain Controller for verification.
5. The Domain Controller recalculates the response and compares it to the client's response:
   - If they match, the client is authenticated.
   - If they do not match, access is denied.
6. Authentication results are forwarded back to the client.

### Note
- When using a **local account**, the server validates the response directly using the locally stored password hash in the Security Account Manager (SAM).

---

## Key Differences
| Feature         | Kerberos                      | NetNTLM                      |
|------------------|-------------------------------|-------------------------------|
| **Default Use**  | Modern Windows domains        | Legacy protocol for compatibility. |
| **Mechanism**    | Ticket-based authentication.  | Challenge-response mechanism. |
| **Password**     | Not transmitted over network. | Not transmitted over network. |

---

## Conclusion
- **Kerberos** is the recommended and more secure protocol for modern domains.
- **NetNTLM** should be phased out but is still present for legacy support.

# Active Directory: Managing Multiple Domains

## Single Domain
- **Definition**: A single domain is sufficient for small or growing businesses.
- **Limitations**:
  - Hard to manage complex structures as the company grows.
  - Difficult to accommodate regional compliance or independent IT management.

---

## Trees
- **Definition**: A structure that joins multiple domains sharing the same namespace.
- **Example**:
  - Root domain: `thm.local`
  - Subdomains: `uk.thm.local`, `us.thm.local`
- **Advantages**:
  - Independent management for subdomains (e.g., UK IT team handles `uk.thm.local`).
  - Policies can be configured independently for each domain.
  - Improved security by limiting administrative privileges to specific subdomains.
- **Enterprise Admins**:
  - Users in this group have administrative privileges across all domains in the tree.
  - Each domain still has its own **Domain Admins**.

---

## Forests
- **Definition**: A collection of multiple domain trees with different namespaces.
- **Example**:
  - Tree 1: `thm.local`, `uk.thm.local`, `us.thm.local`
  - Tree 2: `mht.com`, `asia.mht.com`
- **Use Case**: Merging networks of different companies or subsidiaries.
- **Benefits**:
  - Allows integration while maintaining independent management for each tree.

---

## Trust Relationships
- **Purpose**: Enables users from one domain to access resources in another.
- **Types**:
  - **One-Way Trust**:
    - Directional: Domain A trusts Domain B, so users in B can access A's resources.
    - Example: `BBB` → `AAA` (trust direction opposite to access).
  - **Two-Way Trust**:
    - Mutual access: Both domains trust each other.
    - Default for domains in the same tree or forest.
- **Key Points**:
  - Trust relationships don't grant automatic access; specific authorisations are required.
  - Flexibility in granting or restricting cross-domain resource access.

---

## Summary
- **Trees**:
  - Use shared namespaces to organise multiple domains.
  - Ideal for large organisations with regional needs.
- **Forests**:
  - Use different namespaces for managing independent domain trees.
  - Suitable for merging or acquiring new companies.
- **Trusts**:
  - Enable resource sharing between domains while maintaining control.

