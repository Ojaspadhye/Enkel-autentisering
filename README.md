## Enkel Autentisering ##
"Enkel Autentisering" is a swedish word for "Simple Authentication". This is a simple ready to go modules. That can be plugged in into django and boohm it works.
This is first in list many other repositories for basic modules like uploding images videos, messageing, video brodcasting etc.
Cool !!

**TechStack**
1. JWT
2. Django
3. Djangorestframework
4. OAutha2

**Procidure**
1. Clone the project / starter template
2. Setup environment (venv, dependencies, .env) (do pip install -r reqirements.txt)
3. Update user model if needed (roles, extra fields, flags)
4. Configure DB + Redis (cache, sessions, throttling backend) (in settings as shown down)
5. Setup JWT auth (access, refresh, blacklist if needed)
6. Configure throttling (scope or custom based on use-case)
7. Run migrations + create superuser
8. Wire core services (email, OTP, async tasks if any)
9. BHOOM !! build actual business logic. Let other stupid peps do this shit put your brain in better thing

**Dev setup for testing**
1. Link:(UserAuth) 

**Basic URLS**
1. Link: https://documenter.getpostman.com/view/50616787/2sBXiqDoMs

**Docker Container (Docker Hub)**
Docker Image
1. Link: (UserAuth)

**Production Settings (Refrence)**
1. Link: (UserAuth)

(I love swedish!!)
