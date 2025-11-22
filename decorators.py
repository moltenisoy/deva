"""
Utility decorators for error handling, retry logic, and performance monitoring.

This module provides decorators to improve code reliability and observability
throughout the application.
"""

import functools
import logging
import time
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)


def safe_execute(fallback_value: Any = None, log_error: bool = True):
    """
    Decorador para manejo seguro de excepciones.
    
    Envuelve una función para capturar excepciones y retornar un valor por defecto
    en lugar de propagarlas. Útil para operaciones que pueden fallar pero no deben
    interrumpir el flujo principal.
    
    Args:
        fallback_value: Valor a retornar en caso de excepción
        log_error: Si debe loggear el error (default: True)
    
    Returns:
        Callable: Función decorada con manejo de excepciones
    
    Example:
        >>> @safe_execute(fallback_value=False)
        >>> def risky_operation():
        >>>     # código que puede fallar
        >>>     return True
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
    
    Reintenta la ejecución de una función un número máximo de veces con un
    delay entre intentos. Útil para operaciones que pueden fallar temporalmente
    por condiciones de carrera o recursos temporalmente no disponibles.
    
    Args:
        max_attempts: Número máximo de intentos (default: 3)
        delay_ms: Delay entre intentos en milisegundos (default: 100)
    
    Returns:
        Callable: Función decorada con lógica de reintento
    
    Raises:
        Exception: La última excepción capturada después de agotar todos los intentos
    
    Example:
        >>> @retry(max_attempts=3, delay_ms=500)
        >>> def get_active_scheme_guid() -> Optional[str]:
        >>>     # operación que puede fallar temporalmente
        >>>     return guid
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
    
    Mide el tiempo que tarda en ejecutarse una función y lo registra si excede
    un umbral especificado. Útil para identificar cuellos de botella de rendimiento.
    
    Args:
        log_threshold_ms: Solo loggea si el tiempo de ejecución excede este threshold
                         en milisegundos (default: 100)
    
    Returns:
        Callable: Función decorada con medición de rendimiento
    
    Example:
        >>> @measure_performance(log_threshold_ms=50)
        >>> def apply_power_mode(mode_name: str) -> bool:
        >>>     # operación que queremos monitorear
        >>>     return True
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
