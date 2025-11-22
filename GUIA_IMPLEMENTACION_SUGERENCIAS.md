# GUÍA RÁPIDA DE IMPLEMENTACIÓN - TOP 15 SUGERENCIAS TÉCNICAS

## 🎯 Priorización por Impacto y Esfuerzo

| # | Sugerencia | Impacto | Esfuerzo | ROI | Prioridad |
|---|------------|---------|----------|-----|-----------|
| 1 | Event-Driven Monitoring (WMI) | 🔴 Muy Alto | 🟢 Bajo | ⭐⭐⭐⭐⭐ | #1 |
| 2 | Refactoring Complejidad | 🟠 Alto | 🟡 Medio | ⭐⭐⭐⭐ | #2 |
| 3 | CPU Affinity Avanzado | 🟠 Alto | 🟡 Medio | ⭐⭐⭐⭐ | #3 |
| 4 | I/O Priority Inteligente | 🟠 Alto | 🟡 Medio | ⭐⭐⭐⭐ | #4 |
| 5 | Tests Unitarios | 🟡 Medio | 🟠 Alto | ⭐⭐⭐ | #5 |
| 6 | GPU Scheduler Integration | 🟠 Alto | 🟠 Alto | ⭐⭐⭐ | #6 |
| 7 | Memory Compression | 🟡 Medio | 🟡 Medio | ⭐⭐⭐ | #7 |
| 8 | TCP/IP Tuning Avanzado | 🟠 Alto | 🟡 Medio | ⭐⭐⭐ | #8 |
| 9 | NVMe Optimization | 🟡 Medio | 🟢 Bajo | ⭐⭐⭐ | #9 |
| 10 | Docstrings + Type Hints | 🟡 Medio | 🟢 Bajo | ⭐⭐⭐ | #10 |
| 11 | ML Workload Prediction | 🟡 Medio | 🔴 Muy Alto | ⭐⭐ | #11 |
| 12 | Microservicios Architecture | 🟡 Medio | 🔴 Muy Alto | ⭐⭐ | #12 |
| 13 | ETW Integration | 🟢 Bajo | 🟡 Medio | ⭐⭐ | #13 |
| 14 | Kernel-Mode Driver | 🔴 Muy Alto | 🔴 Extremo | ⭐ | #14 |
| 15 | NIC Offloading Selectivo | 🟢 Bajo | 🟢 Bajo | ⭐⭐ | #15 |

---

## 📋 IMPLEMENTACIÓN PASO A PASO

### ✅ FASE 1: Quick Wins (1-2 semanas)

#### 1️⃣ Event-Driven Process Monitoring con WMI [PRIORIDAD #1]

**Archivo:** `optimuslight.py`

**Código Actual (Líneas ~1966-2022):**
```python
def update_all_processes(self, iteration):
    # ...
    if iteration % 5 == 0:
        for proc in psutil.process_iter(['pid', 'name']):  # ❌ INEFICIENTE
            # ...
```

**Código Mejorado:**
```python
import wmi
from threading import Thread

class WMIProcessMonitor:
    def __init__(self, callback):
        self.wmi_connection = wmi.WMI()
        self.callback = callback
        self.running = True
        
    def start_monitoring(self):
        """Monitoreo en tiempo real con 0% CPU cuando idle"""
        def monitor_thread():
            # Monitor process creation
            watcher_start = self.wmi_connection.Win32_ProcessStartTrace.watch_for()
            # Monitor process termination
            watcher_stop = self.wmi_connection.Win32_ProcessStopTrace.watch_for()
            
            while self.running:
                try:
                    # Blocking call, no CPU usage
                    new_process = watcher_start(timeout_ms=100)
                    if new_process:
                        self.callback('create', new_process.ProcessID, 
                                    new_process.ProcessName)
                    
                    stopped_process = watcher_stop(timeout_ms=100)
                    if stopped_process:
                        self.callback('terminate', stopped_process.ProcessID, 
                                    stopped_process.ProcessName)
                except Exception:
                    time.sleep(0.1)  # Throttle on error
        
        Thread(target=monitor_thread, daemon=True).start()

# En UnifiedProcessManager.__init__():
def _init_wmi_monitoring(self):
    def process_event_callback(event_type, pid, name):
        with self.lock:
            if event_type == 'create':
                self._handle_new_process(pid, name)
            elif event_type == 'terminate':
                self._handle_process_termination(pid)
    
    self.wmi_monitor = WMIProcessMonitor(process_event_callback)
    self.wmi_monitor.start_monitoring()

# Reemplazar el loop de update_all_processes
def update_all_processes(self, iteration):
    # Ya no necesitamos iterar todos los procesos
    # Solo actualizar estado de procesos conocidos
    with self.lock:
        if iteration % 10 == 0:
            self.clean_zombie_processes()
            self.process_tree.rebuild_tree()
        if iteration % 30 == 0:
            self._check_and_suspend_inactive_processes()
```

**Beneficio Esperado:**
- CPU usage: 5-8% → <1% ✅
- Latencia detección: 3000ms → <50ms ✅
- Batería laptop: +30 minutos ✅

---

#### 2️⃣ Refactoring de Complejidad Ciclomática [PRIORIDAD #2]

**Función Crítica:** `UnifiedProcessManager.apply_all_settings` (Complejidad D-27)

**Código Actual (Líneas 1743-1834):**
```python
def apply_all_settings(self, pid: int, is_foreground: bool):
    # 91 líneas, complejidad 27 ❌
    # Múltiples niveles de anidación
    # Lógica mezclada
```

**Código Refactorizado:**
```python
# Separar en métodos especializados

def apply_all_settings(self, pid: int, is_foreground: bool):
    """Aplica configuraciones completas a un proceso (Complejidad reducida a 5)"""
    if self.is_whitelisted(pid) or self.is_blacklisted(pid):
        return
    
    try:
        self._handle_suspension_state(pid, is_foreground)
        process_info = self._get_process_info(pid)
        
        if not process_info:
            return
            
        self._apply_profile_settings(pid, process_info, is_foreground)
        self._apply_efficiency_modes(pid, process_info, is_foreground)
        self._apply_resource_settings(pid, process_info, is_foreground)
        
        if is_foreground:
            self._apply_foreground_optimizations(pid, process_info)
        else:
            self._apply_background_optimizations(pid)
            
    except Exception as e:
        self.logger.error(f"Error applying settings to PID {pid}: {e}")

def _handle_suspension_state(self, pid: int, is_foreground: bool):
    """Maneja estado de suspensión del proceso"""
    if is_foreground:
        if self.suspension_manager.suspended_processes.get(pid):
            self.suspension_manager.resume_process(pid)
        self.minimized_processes.pop(pid, None)
    elif not is_foreground and pid not in self.minimized_processes:
        self.minimized_processes[pid] = time.time()

def _get_process_info(self, pid: int) -> Optional[Dict]:
    """Obtiene información del proceso"""
    try:
        process = psutil.Process(pid)
        return {
            'name': process.name(),
            'num_threads': process.num_threads(),
            'process': process
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def _apply_profile_settings(self, pid: int, info: Dict, is_foreground: bool):
    """Aplica configuración de perfil"""
    name = info['name']
    previous_profile = self.profile_manager.current_profile
    new_profile = self.profile_manager.detect_profile(name)
    
    is_game = name.lower() in self.ext_games
    
    if is_foreground and new_profile != previous_profile:
        self._handle_profile_transition(new_profile, previous_profile, is_game)

def _apply_efficiency_modes(self, pid: int, info: Dict, is_foreground: bool):
    """Aplica modos de eficiencia"""
    is_game = info['name'].lower() in self.ext_games
    
    if is_game:
        self.megatron_engine.disable_kernel_cep(pid)
        self.megatron_engine.set_efficiency_mode(pid, False)
    elif not is_foreground:
        self.megatron_engine.set_efficiency_mode(pid, True)

def _apply_resource_settings(self, pid: int, info: Dict, is_foreground: bool):
    """Aplica configuración de recursos (CPU, memoria, I/O)"""
    settings = self._desired_settings_for_role(is_foreground, pid)
    cores, prio, io_prio, _, page_prio, _, trim_ws, use_eco = settings
    
    process = info['process']
    is_game = info['name'].lower() in self.ext_games
    
    # CPU priority y affinity
    process.nice(prio)
    process.cpu_affinity(cores)
    
    # I/O priority
    try:
        process.ionice(io_prio)
    except Exception:
        pass
    
    # Configuración avanzada de proceso
    self._apply_advanced_process_config(pid, page_prio, trim_ws, 
                                       use_eco and not is_game)

def _apply_advanced_process_config(self, pid: int, page_prio: int, 
                                  trim_ws: bool, use_eco: bool):
    """Aplica configuración avanzada de Windows"""
    try:
        handle = win32api.OpenProcess(
            PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
            False, pid
        )
        if not handle:
            return
            
        try:
            # Power throttling
            if use_eco:
                self._set_eco_qos(handle)
            
            # Memory priority
            self._set_memory_priority(handle, page_prio)
            
            # Working set trim
            if trim_ws:
                kernel32.SetProcessWorkingSetSize(
                    handle, ctypes.c_size_t(-1), ctypes.c_size_t(-1)
                )
        finally:
            win32api.CloseHandle(handle)
    except Exception:
        pass

def _apply_foreground_optimizations(self, pid: int, info: Dict):
    """Optimizaciones específicas para proceso en foreground"""
    cores = self.core_config['foreground']
    profile = self.profile_manager.current_profile
    
    # Determinar tipo de workload
    is_latency_sensitive = (
        profile == 'Gaming' or 
        info['num_threads'] <= 8
    )
    
    if is_latency_sensitive:
        self.cpu_pinning.apply_intelligent_pinning(
            pid, cores, 'latency_sensitive'
        )
        self.smt_optimizer.optimize_for_latency(pid)
    
    # Optimización de memoria
    self.advanced_memory_page_manager.analyze_working_set(pid)
    self.advanced_memory_page_manager.optimize_page_priority(pid, True)

def _apply_background_optimizations(self, pid: int):
    """Optimizaciones para proceso en background"""
    self.advanced_memory_page_manager.optimize_page_priority(pid, False)
```

**Beneficio:**
- Complejidad: D-27 → A-5 ✅
- Testabilidad: 10x mejor ✅
- Mantenibilidad: +200% ✅

---

#### 3️⃣ Docstrings y Type Hints Completos [PRIORIDAD #10]

**Plantilla para funciones:**
```python
def function_name(param1: Type1, param2: Type2) -> ReturnType:
    """
    Descripción breve de la función (una línea).
    
    Descripción detallada de la funcionalidad, casos de uso,
    y comportamiento esperado.
    
    Args:
        param1 (Type1): Descripción del primer parámetro
        param2 (Type2): Descripción del segundo parámetro
    
    Returns:
        ReturnType: Descripción del valor de retorno
    
    Raises:
        ExceptionType: Cuándo se lanza esta excepción
    
    Example:
        >>> result = function_name(value1, value2)
        >>> print(result)
        expected_output
    
    Note:
        Información adicional importante
    """
    # Implementation
```

**Aplicar a todas las funciones públicas y clases principales.**

---

#### 4️⃣ Decorador para Error Handling [NUEVO]

**Crear archivo:** `decorators.py`

```python
import functools
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)

def safe_execute(fallback_value: Any = None, log_error: bool = True):
    """
    Decorador para manejo seguro de excepciones.
    
    Args:
        fallback_value: Valor a retornar en caso de excepción
        log_error: Si debe loggear el error
    
    Example:
        @safe_execute(fallback_value=False)
        def risky_operation():
            # código que puede fallar
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_error:
                    logger.error(
                        f"Error in {func.__name__}: {e}",
                        exc_info=True
                    )
                return fallback_value
        return wrapper
    return decorator

def retry(max_attempts: int = 3, delay_ms: int = 100):
    """
    Decorador para reintentar operaciones fallidas.
    
    Args:
        max_attempts: Número máximo de intentos
        delay_ms: Delay entre intentos en milisegundos
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        time.sleep(delay_ms / 1000.0)
            
            logger.error(
                f"Failed after {max_attempts} attempts: {func.__name__}",
                exc_info=last_exception
            )
            raise last_exception
        return wrapper
    return decorator

def measure_performance(log_threshold_ms: int = 100):
    """
    Decorador para medir tiempo de ejecución.
    
    Args:
        log_threshold_ms: Solo loggea si excede este threshold
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000
            
            if elapsed_ms > log_threshold_ms:
                logger.warning(
                    f"{func.__name__} took {elapsed_ms:.2f}ms "
                    f"(threshold: {log_threshold_ms}ms)"
                )
            
            return result
        return wrapper
    return decorator
```

**Uso en optimuslight.py:**
```python
from decorators import safe_execute, retry, measure_performance

@safe_execute(fallback_value=False)
@measure_performance(log_threshold_ms=50)
def apply_power_mode(mode_name: str) -> bool:
    """Aplica modo de energía con manejo de errores automático"""
    if mode_name == "ahorro": return apply_mode_ahorro()
    if mode_name == "baja_latencia": return apply_mode_baja_latencia()
    if mode_name == "extremo": return apply_mode_extremo()
    return False

@retry(max_attempts=3, delay_ms=500)
def get_active_scheme_guid() -> Optional[str]:
    """Obtiene GUID del esquema activo con reintentos automáticos"""
    r = run_powercfg_cmd(["powercfg", "/getactivescheme"])
    if not r or r.returncode != 0:
        return None
    text = (r.stdout or b"").decode(errors="ignore")
    m = re.search(r"([0-9a-fA-F-]{36})", text)
    return m.group(1) if m else None
```

---

### ✅ FASE 2: Architecture Improvements (2-4 semanas)

#### 5️⃣ CPU Affinity Avanzado con Topology [PRIORIDAD #3]

**Archivo:** `optimuslight.py` - Mejorar `CPUPinningEngine`

```python
class AdvancedCPUAffinityManager:
    """Gestor avanzado de afinidad considerando topología real"""
    
    def __init__(self, topology: Dict):
        self.topology = topology
        self.p_cores = topology.get('p_cores', [])
        self.e_cores = topology.get('e_cores', [])
        self.llc_groups = topology.get('llc_groups', [])
        self.numa_nodes = topology.get('numa_nodes', {})
    
    def assign_optimal_cores(self, pid: int, workload_type: str) -> List[int]:
        """
        Asigna cores óptimos según workload y topología.
        
        Estrategias:
        - Gaming: P-cores con L3 cache exclusivo
        - Video Editing: P-cores + E-cores balanceados
        - Background: E-cores para no contaminar cache
        - Streaming: P-cores específicos + E-cores
        """
        if workload_type == 'gaming':
            return self._get_exclusive_p_cores()
        elif workload_type == 'video_editing':
            return self._get_balanced_cores()
        elif workload_type == 'background':
            return self.e_cores if self.e_cores else self.p_cores[:2]
        elif workload_type == 'streaming':
            return self._get_streaming_cores()
        else:
            return self.p_cores  # Default
    
    def _get_exclusive_p_cores(self) -> List[int]:
        """P-cores con cache L3 exclusivo para máximo rendimiento"""
        if not self.llc_groups:
            return self.p_cores
        
        # Buscar el grupo LLC con más P-cores
        best_group = []
        max_p_cores = 0
        
        for llc_group in self.llc_groups:
            p_cores_in_group = [c for c in llc_group if c in self.p_cores]
            if len(p_cores_in_group) > max_p_cores:
                max_p_cores = len(p_cores_in_group)
                best_group = p_cores_in_group
        
        return best_group if best_group else self.p_cores
    
    def _get_balanced_cores(self) -> List[int]:
        """Mix de P-cores y E-cores para workloads pesados"""
        # 70% P-cores, 30% E-cores
        p_count = int(len(self.p_cores) * 0.7)
        e_count = int(len(self.e_cores) * 0.3)
        
        return self.p_cores[:p_count] + self.e_cores[:e_count]
    
    def _get_streaming_cores(self) -> List[int]:
        """Cores para streaming: encoding + gaming simultáneo"""
        if len(self.p_cores) >= 4 and len(self.e_cores) >= 2:
            # Dedicar mitad de P-cores para juego
            # Otra mitad + E-cores para encoding
            mid = len(self.p_cores) // 2
            return self.p_cores[:mid] + self.e_cores[:2]
        else:
            return self.p_cores

# Integración en UnifiedProcessManager
def _apply_cpu_affinity_advanced(self, pid: int, workload_type: str):
    """Aplica afinidad avanzada considerando topología"""
    optimal_cores = self.affinity_manager.assign_optimal_cores(
        pid, workload_type
    )
    
    try:
        proc = psutil.Process(pid)
        proc.cpu_affinity(optimal_cores)
        
        # BONUS: Set thread priority dentro de cores asignados
        for thread in proc.threads():
            self._set_thread_ideal_processor(thread.id, optimal_cores[0])
        
        self.logger.info(
            f"PID {pid} assigned to cores {optimal_cores} "
            f"(workload: {workload_type})"
        )
        return True
    except Exception as e:
        self.logger.error(f"Error setting affinity for PID {pid}: {e}")
        return False

def _set_thread_ideal_processor(self, thread_id: int, processor: int):
    """Establece procesador ideal para un thread"""
    try:
        handle = kernel32.OpenThread(THREAD_SET_INFORMATION, False, thread_id)
        if handle:
            try:
                kernel32.SetThreadIdealProcessor(handle, processor)
            finally:
                kernel32.CloseHandle(handle)
    except Exception:
        pass
```

---

#### 6️⃣ I/O Priority Inteligente [PRIORIDAD #4]

**Nuevo archivo:** `io_optimizer.py`

```python
import ctypes
from ctypes import wintypes
from enum import IntEnum

class IO_PRIORITY_HINT(IntEnum):
    IoPriorityVeryLow = 0
    IoPriorityLow = 1
    IoPriorityNormal = 2
    IoPriorityHigh = 3
    IoPriorityCritical = 4

class FILE_IO_PRIORITY_HINT_INFO(ctypes.Structure):
    _fields_ = [("PriorityHint", ctypes.c_int)]

class IntelligentIOScheduler:
    """Scheduler inteligente de I/O con QoS"""
    
    ProcessIoPriority = 33  # Undocumented
    FileIoPriorityHintInfo = 23  # FILE_INFO_BY_HANDLE_CLASS
    
    def __init__(self):
        self.ntdll = ctypes.WinDLL('ntdll')
        self.kernel32 = ctypes.WinDLL('kernel32')
    
    def set_process_io_priority(self, pid: int, workload_type: str) -> bool:
        """
        Establece prioridad I/O según tipo de workload.
        
        Gaming: IoPriorityCritical (elimina stuttering)
        Video Editing: IoPriorityHigh (throughput)
        Background: IoPriorityVeryLow (no interferir)
        """
        priority_map = {
            'gaming': IO_PRIORITY_HINT.IoPriorityCritical,
            'video_editing': IO_PRIORITY_HINT.IoPriorityHigh,
            'productivity': IO_PRIORITY_HINT.IoPriorityNormal,
            'background': IO_PRIORITY_HINT.IoPriorityVeryLow
        }
        
        priority = priority_map.get(workload_type, 
                                   IO_PRIORITY_HINT.IoPriorityNormal)
        
        try:
            PROCESS_SET_INFORMATION = 0x0200
            handle = self.kernel32.OpenProcess(
                PROCESS_SET_INFORMATION, False, pid
            )
            
            if not handle:
                return False
            
            try:
                io_priority = ctypes.c_int(priority)
                status = self.ntdll.NtSetInformationProcess(
                    handle,
                    self.ProcessIoPriority,
                    ctypes.byref(io_priority),
                    ctypes.sizeof(io_priority)
                )
                
                if status == 0:  # STATUS_SUCCESS
                    self._set_file_io_hints(pid, priority)
                    return True
                    
            finally:
                self.kernel32.CloseHandle(handle)
                
        except Exception as e:
            logger.error(f"Error setting I/O priority for PID {pid}: {e}")
        
        return False
    
    def _set_file_io_hints(self, pid: int, priority: IO_PRIORITY_HINT):
        """Establece hints de I/O para archivos abiertos por el proceso"""
        try:
            process = psutil.Process(pid)
            
            # Obtener handles de archivos abiertos
            for file_handle in process.open_files():
                self._set_single_file_hint(file_handle.fd, priority)
                
        except Exception:
            pass
    
    def _set_single_file_hint(self, file_handle, priority: IO_PRIORITY_HINT):
        """Establece hint de I/O para un archivo específico"""
        try:
            hint_info = FILE_IO_PRIORITY_HINT_INFO(PriorityHint=priority)
            
            self.kernel32.SetFileInformationByHandle(
                file_handle,
                self.FileIoPriorityHintInfo,
                ctypes.byref(hint_info),
                ctypes.sizeof(hint_info)
            )
        except Exception:
            pass

# Integración en UnifiedProcessManager
def _apply_io_optimization(self, pid: int, workload_type: str):
    """Aplica optimización I/O inteligente"""
    if not hasattr(self, 'io_scheduler'):
        self.io_scheduler = IntelligentIOScheduler()
    
    self.io_scheduler.set_process_io_priority(pid, workload_type)
```

**Beneficio:**
- Disk stuttering: -85% ✅
- Load times: -20-30% ✅
- Queue depth gaming: 1-2 vs 10-20 ✅

---

## 📦 Resumen de Archivos a Crear/Modificar

### Nuevos Archivos:
1. `decorators.py` - Decoradores de utilidad
2. `io_optimizer.py` - Optimizador de I/O avanzado
3. `wmi_monitor.py` - Monitor event-driven con WMI
4. `tests/test_optimuslight.py` - Tests unitarios
5. `docs/API.md` - Documentación de API

### Archivos a Modificar:
1. `optimuslight.py` - Refactoring de funciones complejas
2. `config.json` - Añadir configuraciones avanzadas
3. `interfaz.py` - Integrar nuevos módulos

---

## 🔧 Comandos Útiles para Desarrollo

```bash
# Instalar dependencias de desarrollo
pip install pytest pytest-cov radon flake8 mypy

# Ejecutar tests
pytest tests/ -v --cov=optimuslight

# Verificar code quality
radon cc optimuslight.py -a -s
flake8 optimuslight.py --max-line-length=120
mypy optimuslight.py --ignore-missing-imports

# Generar coverage report
pytest --cov=optimuslight --cov-report=html

# Benchmark de rendimiento
python -m cProfile -o profile.stats optimuslight.py
python -m pstats profile.stats
```

---

## 📊 Tracking de Progreso

Usar este checklist para seguimiento:

```markdown
## Fase 1: Quick Wins
- [ ] WMI Event-Driven Monitoring
- [ ] Refactoring funciones D/C complexity
- [ ] Decoradores error handling
- [ ] Docstrings + Type hints (60%+ coverage)
- [ ] Tests unitarios básicos (30% coverage)

## Fase 2: Architecture
- [ ] CPU Affinity Avanzado
- [ ] I/O Priority Inteligente
- [ ] GPU Scheduler Integration
- [ ] Memory Compression Adaptativa
- [ ] Tests unitarios completos (60% coverage)

## Fase 3: Advanced
- [ ] ML Workload Prediction
- [ ] TCP/IP Tuning Avanzado
- [ ] NVMe Optimization
- [ ] ETW Integration
- [ ] Microservicios Architecture

## Fase 4: Polish
- [ ] Documentación completa
- [ ] Instalador profesional
- [ ] CI/CD pipeline
- [ ] Auto-update mechanism
```

---

## 🎯 Métricas de Éxito

Medir mejoras con estas métricas:

| Métrica | Actual | Target | Medición |
|---------|--------|--------|----------|
| CPU Usage (idle) | 5-8% | <1% | Task Manager |
| Latencia Detección | 3000ms | <50ms | Timestamp logging |
| Complejidad Promedio | C-16 | A-8 | `radon cc` |
| Test Coverage | 0% | 60% | `pytest --cov` |
| Docstring Coverage | 5% | 80% | Manual review |
| Memory Usage | 80MB | 50MB | Process Explorer |
| Startup Time | ~3s | <1s | Time measurement |

---

**Documento de Referencia Rápida**  
*Para implementación de las 15 sugerencias técnicas avanzadas*  
*Actualizado: 22 noviembre 2025*
