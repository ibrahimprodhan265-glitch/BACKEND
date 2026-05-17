# Hyper Regedit Backend - Render Web Service

এই folder-টা আলাদা GitHub repo হিসেবে upload করবেন।

## এই repo কী

এটা শুধু backend API:

- Admin login API
- User login API
- Admin-created username/password auth
- Device ID lock
- Package status check
- Expire date check
- Maintenance mode
- Options/packages/users/settings/logs API
- App icon এবং login background settings storage
- Neon PostgreSQL schema

## GitHub Upload

এই folder-এর সব file GitHub repo-তে upload করবেন:

```text
hyper-regedit-backend-render
```

Upload করবেন:

```text
db
.env.example
.gitignore
BACKEND_RENDER_GUIDE_BN.md
index.cjs
package.json
render.yaml
```

Upload করবেন না:

```text
node_modules
.env
data
```

## Render Deploy

Render Dashboard > New > Web Service

Settings:

```text
Root Directory: blank রাখবেন
Runtime: Node
Build Command: npm install
Start Command: npm start
Health Check Path: /api/health
```

Environment Variables:

```text
DATABASE_URL=your_neon_postgres_connection_string
CLIENT_ORIGIN=https://your-frontend.onrender.com
TOKEN_SECRET=any-long-random-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=ADMIN-2026
PUBLIC_APP_URL=https://your-frontend.onrender.com/app
```

## Admin Login

Admin panel frontend URL-এ থাকবে:

```text
https://your-frontend.onrender.com/admin
```

Default admin:

```text
Username: admin
Password: ADMIN-2026
```

Production-এর জন্য Render backend Environment tab থেকে `ADMIN_PASSWORD` strong password করে দেবেন।

Important: backend first deploy হলে default admin database-এ create হবে। পরে `ADMIN_PASSWORD` বদলালে পুরনো DB admin password auto-change হবে না। তখন Neon DB row update করতে হবে অথবা fresh database use করতে হবে।

## Neon Database

Neon connection string:

```text
postgresql://USER:PASSWORD@HOST.neon.tech/DB?sslmode=require
```

Render backend-এর `DATABASE_URL`-এ বসাবেন।

Schema file:

```text
db/schema.sql
```

Backend start হলে schema auto-create করবে।

## Check Backend

Deploy হলে open করুন:

```text
https://your-backend-service.onrender.com/api/health
```

Response OK হলে frontend-এর `VITE_API_URL`-এ এই backend URL বসাবেন।

## Official Docs

- Render Node Express: https://render.com/docs/deploy-node-express-app
- Render Web Services: https://render.com/docs/web-services/
