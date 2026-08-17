# EduFriends — servidor online listo para Render

Esta versión usa **Render Web Service + Render Postgres**. No usa SQLite, porque el filesystem de un servicio Free de Render es efímero y los cambios locales se pierden al reiniciar/redeployar.

## Despliegue
1. Sube esta carpeta a un repositorio GitHub.
2. En Render: **New → Blueprint** y selecciona ese repositorio.
3. Render leerá `render.yaml` y creará el servicio `edufriends-api` y la base `edufriends-db`.
4. Espera a que ambos queden en estado activo.
5. Abre la URL `https://<tu-servicio>.onrender.com/api/health`.
6. Debe responder JSON con `ok: true` y `database: "postgres"`.
7. Abre `https://<tu-servicio>.onrender.com/admin` para el panel administrativo. Usa el valor generado para `ADMIN_KEY` que aparece en las variables de entorno del servicio.

## API
- POST `/api/register`
- POST `/api/login`
- GET `/api/me` (Bearer token)
- PUT `/api/me` (Bearer token)
- GET `/api/rankings?course=Matemáticas`
- GET `/api/admin/users` (header `X-Admin-Key`)
- GET `/api/health`

## Importante sobre el plan Free
Render ofrece Web Service y Postgres Free para pruebas, pero el Web Service puede dormir tras 15 minutos sin tráfico y la base Postgres Free expira después de 30 días. Para EduFriends como aplicación real con datos permanentes, conviene actualizar la base a un plan de pago antes de esos 30 días.
