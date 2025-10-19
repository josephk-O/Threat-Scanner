
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Union
from logging.handlers import RotatingFileHandler
from functools import wraps
from time import perf_counter

class ThreatLogger:
    
    _loggers: Dict[str, logging.Logger] = {}
    
    def __init__(
        self, 
        service_name: str, 
        logger_level: str = 'DEBUG',
        log_dir: str= '../logs',
        max_bytes: int = 10_485_760, 
        backup_count: int = 5,
        log_format: Optional[str] = None
        ):
        
        self.service_name = service_name
        self.logger_level = logger_level.upper()
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.logging = logging.getLogger(self.service_name)
        
        if service_name in self._loggers:
            self.logger = self._loggers[service_name]
        else:
            self.logger = self._setup_logger(max_bytes, backup_count, log_format)
            self._loggers[service_name] =self.logger
            
    def _setup_logger(self, max_bytes: int, backup_count: int, log_format: Optional[str]) -> logging.Logger:
        logger = logging.getLogger(self.service_name)
    
        logger.handlers.clear()
    
        log_file = self.log_dir / f"{self.service_name}.log"
        file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
        )
        stream_handler = logging.StreamHandler()
        
        if log_format is None:
            log_format = '%(asctime)s - %(name)s - [%(levelname)s] - %(filename)s:%(lineno)d - %(message)s'
    
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
        try:
            level = getattr(logging, self.logger_level)
            logger.setLevel(level)
        except AttributeError:
            logger.setLevel(logging.INFO)
            logger.warning(f"Invalid log level '{self.logger_level}', defaulting to INFO")
    
        logger.propagate = False
        return logger
    
    
    def info(self, message: str, **kwargs) ->None:
        self.logging.info(message, **kwargs)
    
    def debug(self, message: str, **kwargs) -> None:
        self.logging.debug(message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        self.logging.warning(message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        self.logging.critical(message, **kwargs)
    
    def error(self, message: str, exc_info: bool=True, **kwargs) -> None:
        self.logging.error(message, exc_info=exc_info, **kwargs)
    
    def exception(self, message, **kwargs) -> None:
        self.logging.exception(message, **kwargs)
    
    def set_level(self, level: str) -> None:
        try:
            self.logger.setLevel(getattr(logging, level.upper()))
            self.logger_level = level.upper()
        except AttributeError:
            self.logger.warning(f"Invalid log level: {level}")   


class ThreatScanLogger(ThreatLogger):
    
    def scan_started(self, target: str, service: str) -> None:
        self.info(f"Scan started - Target: {target}, Service: {service}")
    
    def threat_detected(self, threat_type: str, severity: str, details: Dict[str, Any]) -> None:
        self.warning(
            f"THREAT DETECTED - Type: {threat_type}, Severity: {severity}",
            extra={"threat_details": details}
        )
    
    def scan_completed(self, target: str, threats_found: int, duration: float) -> None:
        level = self.warning if threats_found > 0 else self.info
        level(f"Scan completed - Target: {target}, Threats: {threats_found}, Duration: {duration:.2f}s")

    def timed_scan(
        self,
        service: Union[str, Callable[..., str]],
        target_resolver: Optional[Callable[..., str]] = None,
        threat_counter: Optional[Callable[[Any, str, str], int]] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            def wrapper(*args, **kwargs):
                target = self._resolve_target(args, kwargs, target_resolver)
                service_name = service(*args, **kwargs) if callable(service) else service
                self.scan_started(target, service_name)
                start = perf_counter()
                try:
                    result = func(*args, **kwargs)
                except Exception:
                    duration = perf_counter() - start
                    self.scan_completed(target, threats_found=0, duration=duration)
                    raise
                duration = perf_counter() - start

                threats_found = 0
                if threat_counter is not None:
                    try:
                        threats_found = threat_counter(result, target, service_name)
                    except Exception as threat_error:
                        self.warning(
                            "Threat counter failed",
                            extra={
                                "target": target,
                                "service": service_name,
                                "error": str(threat_error),
                            },
                        )

                self.scan_completed(target, threats_found=threats_found, duration=duration)
                return result

            return wrapper

        return decorator

    def _resolve_target(
        self,
        args: tuple,
        kwargs: Dict[str, Any],
        target_resolver: Optional[Callable[..., str]] = None,
    ) -> str:
        if target_resolver is not None:
            return target_resolver(*args, **kwargs)
        if args:
            candidate = args[0]
        else:
            candidate = kwargs.get("ip") or kwargs.get("target")
        return str(candidate) if candidate is not None else "<unknown>"



# threat_logger = ThreatLogger('threat_intel', 'debug')

# threat_logger.debug('this is info logger')
# threat_logger.info('this is the debug logger')
# threat_logger.critical('this is info logger')
# threat_logger.error('this is the debug logger')
# threat_logger.warning('this is info logger')
# threat_logger.info('this is the debug logger')
