# VulnTour  

VulnTour is a lightweight Single-Page Application (SPA) built with:

- Vanilla JavaScript (frontend)
- Node.js + Express (backend APIs)
- SQLite (database)
- JWT-based authentication
- Fully asynchronous JSON APIs

Its architecture resembles real-world production systems, using role-based UI rendering, persistent dashboards, API-driven workflows, and token-based auth — making it perfect for realistic yet approachable security testing.  


### Why VulnTour Exists  

It is intentionally designed as a hands-on vulnerable playground where testers can practice:

- Exploiting insecure JWT implementations
- Attacking broken authentication & sessions
- Bypassing flawed access control
- Performing injection attacks
- Enumeration, privilege escalation & token tampering  

Every weakness is intentionally aligned with **OWASP Top 10** to mimic real attack paths found in production.  

#### Two-Tier Architecture  

- Frontend (Nginx – alpine): Serves the SPA with fast, lightweight static delivery.
- Backend (Node.js 20-slim + Express): Handles all API routes, JWT authentication, and database operations.  

This simple two-tier setup mirrors real-world production deployments.  


#### Your mission is simple:  

- Probe every API endpoint
- Manipulate every JWT
- Break assumptions, trust boundaries, and logic
- Exploit the app to its absolute limits  


## Testing  

####  Default Credentials

| **Type** | **Username** | **Password** | **Role** |
|----------|--------------|--------------|----------|
| Admin    | `admin`      | `admin`      | `admin`  |
| User     | `test`       | `test`       | `user`   |

NOTE: New users can be registered!  

## Installation  

```sh
# clone the repository locally  
git clone https://github.com/Debang5hu/VulnTour.git

# cd
cd VulnTour
```  

## Usage  

Ensure docker and docker-compose are installed.  


```sh
# start the containers
docker-compose up -d --build

# stop
docker-compose down
```  


## Bug & Contributions  

- If you find bugs or want to contribute improvements or new features, feel free to **open an issue** or **submit a Pull Request (PR)** on the repository.  
- Community contributions, enhancements, and new ideas are warmly welcome.  



![Static Badge](https://img.shields.io/badge/VulnTour-%3C3-red)  