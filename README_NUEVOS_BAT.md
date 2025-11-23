# Archivos de Optimización Consolidados

Este repositorio contiene 6 archivos .bat que consolidan TODAS las optimizaciones de los 9 archivos originales.

## Archivos Nuevos

### 1. redes.bat (233 líneas)
**Optimizaciones de Red**
- Configuración global TCP/IP
- Parámetros de interfaces activas
- AFD (Ancillary Function Driver)
- NetBIOS deshabilitado
- Lanman optimizado
- QoS y Network Throttling desactivado
- DNS optimizado
- MSI Mode para adaptadores de red
- Configuraciones PowerShell de adaptadores
- Seguridad de red (TLS 1.2/1.3, cifrados inseguros deshabilitados)
- Servicios de red optimizados

### 2. gpuycpu.bat (364 líneas)
**Optimizaciones de GPU y CPU**
- Planificación GPU y prioridades multimedia
- Hardware Accelerated GPU Scheduling
- TDR (Timeout Detection and Recovery)
- Drivers NVIDIA, AMD, Intel optimizados
- Desktop Window Manager (DWM) configurado
- GameDVR y GameBar deshabilitados
- Direct3D y DirectX optimizados
- DirectDraw y DirectMusic
- MSI Mode para GPU
- CSRSS y prioridades de procesos
- Prioridades de juegos específicos
- Configuración de entrada (teclado/mouse)

### 3. servicios.bat (295 líneas)
**Gestión de Servicios**
- Telemetría y diagnósticos deshabilitados
- Windows Error Reporting deshabilitado
- Windows Defender completamente deshabilitado
- Búsqueda e indexación deshabilitadas
- Superfetch y Prefetch deshabilitados
- Servicios de fuentes, biométricos, impresión
- Servicios de mapas y localización
- Servicios Xbox (modo demanda)
- Servicios de actualización (modo demanda)
- Hyper-V deshabilitado
- 100+ servicios adicionales optimizados
- Servicios de Google, Brave, Firefox eliminados

### 4. ramyalmacenamiento.bat (94 líneas)
**Optimizaciones de RAM y Almacenamiento**
- Memoria y paginación optimizada
- Mitigaciones Spectre/Meltdown deshabilitadas (⚠️ RIESGO DE SEGURIDAD)
- FSUtil configurado (compresión, cifrado deshabilitado)
- Ahorro de energía SSD desactivado
- User Write Cache habilitado
- IoLatencyCap optimizado
- System Restore deshabilitado
- Storage Sense deshabilitado
- Limpieza automática de archivos temporales

### 5. kernesybajonivel.bat (123 líneas)
**Optimizaciones de Kernel y Bajo Nivel**
- Validación de cadena de excepciones del kernel deshabilitada
- SEHOP deshabilitado
- Optimizaciones DPC e interrupciones
- BCDEdit tweaks (dynamic tick, platform tick)
- Power throttling desactivado
- C-States gestionados
- MSI Mode para dispositivos PCI
- Gestión de energía USB deshabilitada
- Process Mitigations deshabilitados
- Prioridades de procesos del sistema
- Mantenimiento deshabilitado
- DCOM y FTH deshabilitados

### 6. optimizacionesvarias.bat (539 líneas)
**Optimizaciones Varias**
- Privacidad y telemetría completamente deshabilitada
- Contenido y publicidad bloqueados
- Notificaciones deshabilitadas
- Servicios de localización deshabilitados
- Cortana y búsqueda web deshabilitados
- Windows Feeds deshabilitado
- AppCompat deshabilitado
- Edge telemetría deshabilitada
- OneDrive deshabilitado
- Historial del portapapeles deshabilitado
- Apps en segundo plano bloqueadas
- Explorer tracking deshabilitado
- Office telemetría deshabilitada
- Delivery Optimization configurado
- WindowsAI deshabilitado
- 100+ tareas programadas deshabilitadas
- Bloatware eliminado (40+ aplicaciones)

## Características

✅ **Completamente Automático**: Sin comandos pause, sin confirmaciones, sin advertencias
✅ **Organizado**: Cada archivo tiene secciones claras con comentarios descriptivos
✅ **Sin Duplicados**: Cada ajuste aparece exactamente una vez en todos los archivos
✅ **Completo**: TODOS los ajustes de los 9 archivos originales están incluidos
✅ **Optimizado**: Reducción del 80% en líneas de código (8,542 → 1,648)

## Uso Recomendado

1. **Crear punto de restauración del sistema**
2. **Ejecutar como Administrador**
3. **Aplicar en orden sugerido:**
   - kernesybajonivel.bat
   - ramyalmacenamiento.bat
   - servicios.bat
   - redes.bat
   - gpuycpu.bat
   - optimizacionesvarias.bat

4. **Reiniciar el sistema después de cada archivo** (recomendado)

## Advertencias Importantes

⚠️ **SEGURIDAD**: Estos archivos deshabilitan múltiples características de seguridad:
- Windows Defender
- Mitigaciones Spectre/Meltdown
- Process Mitigations
- Actualizaciones automáticas (set a manual)

⚠️ **ESTABILIDAD**: Estos cambios son agresivos y pueden causar:
- Incompatibilidad con algunos programas
- Problemas con dispositivos específicos
- Necesidad de configuración manual adicional

⚠️ **REVERSIÓN**: Algunos cambios son difíciles de revertir. Se recomienda:
- Crear imagen del sistema antes de aplicar
- Documentar cambios específicos de tu configuración
- Tener conocimientos técnicos para troubleshooting

## Archivos Originales

Los 9 archivos originales siguen disponibles en el repositorio para referencia:
- Ultimate_Optimization.bat
- ajustes_registro.bat
- almacenayhrd.bat
- graficos.bat
- kernelylatencias.bat
- optimizatior2.bat
- optimizeitor.bat
- redes.bat (original)
- serviciosydiagnostico.bat

## Soporte

Para problemas o preguntas, revisar los archivos individuales para entender qué ajustes específicos se están aplicando. Cada sección está claramente comentada.
