# Informe individual — Laboratorio Security as Code

## 1. Datos de entrega
- Nombre: Aura Alba
- Repositorio (fork): https://github.com/AuraAlba/security-as-code-lab
- Rama: `feature/security-lab`

## 2. Análisis inicial
| Herramienta | Archivo/recurso | Hallazgo / regla / CVE | Severidad | Riesgo | Evidencia |
|---|---|---|---|---|---|
| Gitleaks | `src/config.py` (línea 5) / historial Git (3 commits) | Valor ficticio `ghp_0000...` (sin regla disparada en el escaneo: `no leaks found`) | Baja / Informativo (en demo) | Exposición de credenciales en código fuente o historial de Git si el secreto fuera real; además, riesgo de falso negativo por baja entropía/patrón trivial | `evidence/actividad1.png` |
| Checkov | `infra/main.tf` (`aws_s3_bucket.lab_data`, `aws_s3_bucket_acl.lab_data_acl`, `aws_s3_bucket_public_access_block.lab_data`) | 12 políticas fallidas de 17 (destacando `CKV_AWS_20`, `CKV_AWS_53`–`CKV_AWS_56`, `CKV2_AWS_6`, `CKV_AWS_145`, etc.) | Alta / Media | Exposición pública de lectura (`public-read`) y ausencia de bloqueo de acceso público en un bucket S3, con riesgo de filtración de datos | `evidence/actividad2bef.png` |
| Trivy | Imagen `security-as-code-lab:local` (`debian 13.8` y `python-pkg`, incluido `urllib3==1.25.3`) | 53 vulnerabilidades `HIGH` en SO (`debian 13.8`), 7 en `urllib3-1.25.3` y vulnerabilidades en paquetes vendoreados de `setuptools` (`jaraco.context`, `wheel`) | High (0 Critical) | Ejecución de código, escalación de privilegios o denegación de servicio (DoS) por dependencias desactualizadas o fallos en paquetes del sistema base | `evidence/actividad3bef.png` |

## 3. Correcciones realizadas

### Gitleaks (`src/config.py` y `.gitignore`)
- **Causa:** `src/config.py` definía `APP_API_TOKEN` con un valor literal (`"ghp_000000000000000000000000000000000000"`). Aunque Gitleaks no reportó fugas en `gitleaks dir .` ni en `gitleaks git .` por tratarse de un patrón repetitivo/ficticio sin entropía de credencial real, hardcodear tokens es una mala práctica.
- **Cambio realizado:** Se reemplazó el valor literal en `src/config.py` por lectura desde variable de entorno mediante `os.getenv("APP_API_TOKEN", "")` y se verificó que `.env` esté excluido en `.gitignore` sin subir archivos `.env`.
- **Por qué reduce el riesgo:** Evita que secretos de configuración queden escritos en el código fuente y separa la inyección de credenciales al entorno de ejecución (junto con la rotación/limpieza de historial que aplicaría en un incidente real).
- **Resultado del nuevo análisis:** Al volver a ejecutar `gitleaks dir .` y `gitleaks git .`, el escaneo continuó sin hallazgos (`no leaks found`) y sin secretos en el árbol de trabajo.

### Checkov (`infra/main.tf`)
- **Causa:** El recurso `aws_s3_bucket_acl.lab_data_acl` configuraba `acl = "public-read"` y `aws_s3_bucket_public_access_block.lab_data` mantenía en `false` las opciones de bloqueo de ACLs/políticas públicas y restricción de buckets públicos, sin configurar cifrado en reposo de forma explícita.
- **Cambio realizado:** Se cambió el ACL a `"private"`, se habilitaron en `true` los cuatro parámetros de `aws_s3_bucket_public_access_block` (`block_public_acls`, `block_public_policy`, `ignore_public_acls` y `restrict_public_buckets`) y se añadió `aws_s3_bucket_server_side_encryption_configuration` con `AES256`, sin ejecutar `terraform apply`.
- **Por qué reduce el riesgo:** Cierra las vías de exposición pública a nivel de ACL y política/acceso del bucket y garantiza cifrado en reposo para los objetos definidos en la plantilla.
- **Resultado del nuevo análisis:** Tras ejecutar `checkov -d ./infra`, los controles pasaron de 5 a **12 aprobados** (resolviendo `CKV_AWS_20`, `CKV_AWS_53`–`CKV_AWS_56` y `CKV2_AWS_6`), quedando **6 fallidos** asociados a controles adicionales de endurecimiento (`CKV_AWS_18`, `CKV_AWS_21`, `CKV_AWS_144`, `CKV_AWS_145`, `CKV2_AWS_61`, `CKV2_AWS_62`).

### Trivy (`requirements.txt` e imagen `security-as-code-lab:local`)
- **Causa:** `requirements.txt` fijaba `urllib3==1.25.3`, una versión antigua con vulnerabilidades conocidas (`HIGH`), y la imagen se construía sobre `python:3.11-slim` (`debian 13.8`).
- **Cambio realizado:** Se actualizó `urllib3` en `requirements.txt` a `urllib3==2.8.0` y se reconstruyó la imagen local con `docker build -t security-as-code-lab:local .`.
- **Por qué reduce el riesgo:** Elimina las vulnerabilidades `HIGH` asociadas a `urllib3==1.25.3` en la capa de dependencias de la aplicación.
- **Resultado del nuevo análisis:** En el re-escaneo con `trivy image --scanners vuln --severity HIGH,CRITICAL security-as-code-lab:local`, `urllib3-2.8.0` quedó con **0 vulnerabilidades** `HIGH`/`CRITICAL`. Se mantienen **53 hallazgos `HIGH`** en paquetes de `debian 13.8` (muchos sin `Fixed Version` disponible aún) y los hallazgos en paquetes vendoreados de `setuptools` (`jaraco.context-5.3.0` y `wheel-0.45.1`).

## 4. Integración continua
- **Eventos que disparan el workflow (`.github/workflows/security.yml`):** Se ejecuta ante `pull_request` hacia la rama `main` y ante `push` hacia la rama `main`.
- **Permisos configurados:** Se define `permissions: contents: read` a nivel de workflow, aplicando el principio de mínimo privilegio para que las acciones solo lean el código del repositorio sin permisos de escritura innecesarios.
- **Jobs del workflow:**
  1. **`gitleaks` (*Detectar secretos*):** Ejecuta `actions/checkout@v4` con `fetch-depth: 0` para traer el historial Git completo y luego corre `gitleaks/gitleaks-action@v2` con `GITHUB_TOKEN`. Resultado: **aprobado** (`No leaks detected`).
  2. **`checkov` (*Analizar Terraform*):** Ejecuta `actions/checkout@v4` y `bridgecrewio/checkov-action@v12` con `directory: infra` y `framework: terraform`. Resultado: los controles de acceso público y cifrado base pasan, pero el job falla por las 6 reglas adicionales de endurecimiento de S3 (`CKV_AWS_18`, `CKV_AWS_21`, `CKV_AWS_144`, `CKV_AWS_145`, `CKV2_AWS_61`, `CKV2_AWS_62`).
  3. **`trivy` (*Analizar imagen*):** Ejecuta `actions/checkout@v4`, construye la imagen Docker etiquetada con `security-as-code-lab:${{ github.sha }}` y corre `aquasecurity/trivy-action` con `vuln-type: os,library`, `severity: HIGH,CRITICAL` y `exit-code: '1'`. Resultado: en la ejecución inicial (`evidence/actividad4bef.png`) falló por no resolverse la versión `@0.28.0`; al corregir la referencia de la acción, el escaneo corre y el job permanece en fallo (`exit-code: '1'`) debido a las vulnerabilidades `HIGH` residuales en paquetes del SO base (`debian 13.8`) y en librerías vendoreadas de `setuptools`.
- **Resultado del Pull Request:** Pull Request abierto desde `feature/security-lab` hacia `main` en `[Completar URL del PR hacia main]`, documentando el estado de cada job sin ocultar ni desactivar controles.

## 5. Decisiones del desarrollador
- **Decisión 1 — Documentar sin desactivar ni omitir reglas en Checkov y Trivy:** Se decidió no agregar `skip_check` ni `ignore-unfixed` / cambio de `vuln-type` en `.github/workflows/security.yml` para forzar un estado en verde, priorizando la transparencia del diagnóstico y el respeto al alcance del laboratorio (acceso público y cifrado base en S3, y actualización de `urllib3` en la imagen).
- **Decisión 2 — Actualizar solo `urllib3` a `2.8.0` sin modificar la imagen base `python:3.11-slim` ni forzar actualizaciones del SO o `setuptools`:** Se acotó la remediación de dependencias a `requirements.txt` (`urllib3==2.8.0`), evitando cambios innecesarios en la imagen base o paquetes vendoreados fuera del alcance del ejercicio y documentando explícitamente los hallazgos `HIGH` restantes.
- **Recomendación que decidí no aplicar y por qué:** Decidí no aplicar sugerencias orientadas a silenciar o filtrar las alertas de Trivy y Checkov en CI para obtener el check verde en el PR, ya que el objetivo del laboratorio es identificar, interpretar y documentar los hallazgos reales y no ocultar vulnerabilidades del sistema base o políticas no aplicadas en el entorno de prueba.

## 6. Evidencias

### Gitleaks
- **Antes:** ![Gitleaks antes](../evidence/actividad1bef.png)
- **Después:** ![Gitleaks después](../evidence/actividad1aft.png)

### Checkov
- **Antes:** ![Checkov antes](../evidence/actvidad2bef.png)
- **Después:** ![Checkov después](../evidence/actividad2aft.png)

### Trivy
- **Antes:** ![Trivy antes](../evidence/actividad3bef.png)
- **Después:** ![Trivy después](../evidence/actividad3aft.png)

### GitHub Actions y Pull Request
- **GitHub Actions:** ![GitHub Actions](../evidence/actividad4bef.png)
- **Pull Request:** https://github.com/AuraAlba/security-as-code-lab/pull/1/

## 7. Reflexión
1. **¿Qué diferencia hay entre encontrar un problema y prevenir que vuelva a introducirse?**
   Encontrar un problema es una inspección reactiva o puntual sobre el estado actual del código, la infraestructura o la imagen; prevenir que vuelva a introducirse implica automatizar controles continuos (en el editor/pre-commit, en Pull Requests y en CI) que evalúen cada cambio de forma sistemática y alerten o frenen regresiones antes de llegar a `main` o a producción.
2. **¿Qué riesgos no cubren estos tres escáneres?**
   No cubren fallos de lógica de negocio, vulnerabilidades en tiempo de ejecución ni configuraciones dinámicas de la aplicación (como autenticación, autorización, CORS o inyecciones a nivel de lógica de código), ni tampoco la deriva de configuración (*configuration drift*) en entornos reales desplegados fuera del código.
3. **¿Por qué no basta con que el pipeline esté en verde?**
   Porque un pipeline en verde solo indica que se cumplieron las reglas y umbrales configurados en ese momento: puede haber falsos negativos (como tokens con baja entropía), vulnerabilidades de severidad menor o sin parche disponible, problemas de diseño o arquitectura no cubiertos por las herramientas, o excepciones mal acotadas.
4. **¿Qué control agregarías a un proyecto real y por qué?**
   Agregaría un análisis estático de seguridad de código (**SAST**, como Semgrep o CodeQL) en el pipeline y comprobaciones previas al commit (**pre-commit** con Gitleaks), porque complementan a los escáneres actuales detectando patrones inseguros en el código de la aplicación y evitando que secretos se escriban en el historial de Git desde el origen.