"""
Process Manager for WAF + Reverse Proxy

Manages the lifecycle of the Rust binary process, including starting,
stopping, monitoring, and health checking.
"""

import os
import sys
import time
import signal
import psutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
import queue
import logging


@dataclass
class ProcessInfo:
    """Process information structure"""
    pid: int
    status: str
    started_at: datetime
    cpu_percent: float
    memory_mb: float
    threads: int
    open_files: int
    connections: int


class ProcessError(Exception):
    """Process management errors"""
    pass


class ProcessMonitor:
    """Monitor process health and resources"""
    
    def __init__(self, process: psutil.Process, callback: Optional[Callable] = None):
        self.process = process
        self.callback = callback
        self.monitoring = False
        self.monitor_thread = None
        self.stats_history = []
        self.max_history = 100
    
    def start_monitoring(self, interval: float = 5.0):
        """Start process monitoring in background thread"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                if not self.process.is_running():
                    self.monitoring = False
                    if self.callback:
                        self.callback('process_died', {'pid': self.process.pid})
                    break
                
                # Collect stats
                stats = self.get_process_stats()
                self.stats_history.append({
                    'timestamp': datetime.now(),
                    'stats': stats
                })
                
                # Keep only recent history
                if len(self.stats_history) > self.max_history:
                    self.stats_history = self.stats_history[-self.max_history:]
                
                # Check for issues
                if stats.cpu_percent > 90:
                    if self.callback:
                        self.callback('high_cpu', {'cpu_percent': stats.cpu_percent})
                
                if stats.memory_mb > 1024:  # > 1GB
                    if self.callback:
                        self.callback('high_memory', {'memory_mb': stats.memory_mb})
                
                time.sleep(interval)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.monitoring = False
                if self.callback:
                    self.callback('process_lost', {'pid': self.process.pid})
                break
            except Exception as e:
                if self.callback:
                    self.callback('monitor_error', {'error': str(e)})
                time.sleep(interval)
    
    def get_process_stats(self) -> ProcessInfo:
        """Get current process statistics"""
        try:
            with self.process.oneshot():
                return ProcessInfo(
                    pid=self.process.pid,
                    status=self.process.status(),
                    started_at=datetime.fromtimestamp(self.process.create_time()),
                    cpu_percent=self.process.cpu_percent(),
                    memory_mb=self.process.memory_info().rss / 1024 / 1024,
                    threads=self.process.num_threads(),
                    open_files=len(self.process.open_files()),
                    connections=len(self.process.connections())
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            raise ProcessError(f"Cannot get process stats: {e}")
    
    def get_stats_history(self, minutes: int = 10) -> List[Dict]:
        """Get process statistics history"""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [
            entry for entry in self.stats_history
            if entry['timestamp'] >= cutoff
        ]


class ProcessManager:
    """
    Process manager for WAF + Reverse Proxy binary
    
    Handles starting, stopping, restarting, and monitoring the Rust binary process.
    """
    
    def __init__(
        self,
        binary_path: str = "./target/release/waf-reverse-proxy",
        config_path: str = "config/config.yaml",
        working_dir: Optional[str] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize process manager
        
        Args:
            binary_path: Path to the WAF proxy binary
            config_path: Path to configuration file
            working_dir: Working directory for the process
            logger: Logger instance for logging
        """
        self.binary_path = Path(binary_path)
        self.config_path = Path(config_path)
        self.working_dir = Path(working_dir) if working_dir else Path.cwd()
        self.logger = logger or logging.getLogger(__name__)
        
        self.process: Optional[subprocess.Popen] = None
        self.psutil_process: Optional[psutil.Process] = None
        self.monitor: Optional[ProcessMonitor] = None
        self.start_time: Optional[datetime] = None
        
        # Process state
        self.auto_restart = False
        self.restart_count = 0
        self.max_restarts = 5
        self.restart_window = timedelta(minutes=10)
        
        # Logging
        self.log_queue = queue.Queue()
        self.log_thread = None
    
    def start(
        self,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        auto_restart: bool = False,
        validate_config: bool = True
    ) -> bool:
        """
        Start the WAF proxy process
        
        Args:
            args: Additional command line arguments
            env: Environment variables
            auto_restart: Whether to auto-restart on failure
            validate_config: Whether to validate config before starting
            
        Returns:
            True if started successfully
            
        Raises:
            ProcessError: If start fails
        """
        if self.is_running():
            raise ProcessError("Process is already running")
        
        if not self.binary_path.exists():
            raise ProcessError(f"Binary not found: {self.binary_path}")
        
        if not self.config_path.exists():
            raise ProcessError(f"Config file not found: {self.config_path}")
        
        # Validate configuration first if requested
        if validate_config:
            if not self._validate_config():
                raise ProcessError("Configuration validation failed")
        
        # Build command
        cmd = [str(self.binary_path), "--config", str(self.config_path)]
        if args:
            cmd.extend(args)
        
        # Prepare environment
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        try:
            self.logger.info(f"Starting WAF proxy: {' '.join(cmd)}")
            
            # Start process
            self.process = subprocess.Popen(
                cmd,
                cwd=self.working_dir,
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            self.start_time = datetime.now()
            self.auto_restart = auto_restart
            
            # Wait a moment to check if it started successfully
            time.sleep(1)
            
            if self.process.poll() is not None:
                # Process exited immediately
                output = self.process.stdout.read() if self.process.stdout else ""
                raise ProcessError(f"Process failed to start: {output}")
            
            # Create psutil process for monitoring
            self.psutil_process = psutil.Process(self.process.pid)
            
            # Start monitoring
            self.monitor = ProcessMonitor(
                self.psutil_process,
                callback=self._process_event_callback
            )
            self.monitor.start_monitoring()
            
            # Start log capturing
            self._start_log_capture()
            
            self.logger.info(f"WAF proxy started successfully (PID: {self.process.pid})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start process: {e}")
            self.cleanup()
            raise ProcessError(f"Failed to start process: {e}")
    
    def stop(self, timeout: int = 30, force: bool = False) -> bool:
        """
        Stop the WAF proxy process
        
        Args:
            timeout: Timeout in seconds for graceful shutdown
            force: Whether to force kill if graceful shutdown fails
            
        Returns:
            True if stopped successfully
        """
        if not self.is_running():
            self.logger.warning("Process is not running")
            return True
        
        try:
            self.logger.info(f"Stopping WAF proxy (PID: {self.process.pid})")
            
            # Try graceful shutdown first
            if not force:
                self.process.terminate()
                try:
                    self.process.wait(timeout=timeout)
                    self.logger.info("Process stopped gracefully")
                except subprocess.TimeoutExpired:
                    if force:
                        self.logger.warning("Graceful shutdown timed out, forcing kill")
                        self.process.kill()
                        self.process.wait(timeout=5)
                        self.logger.info("Process force killed")
                    else:
                        raise ProcessError("Graceful shutdown timed out")
            else:
                # Force kill immediately
                self.process.kill()
                self.process.wait(timeout=5)
                self.logger.info("Process force killed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop process: {e}")
            raise ProcessError(f"Failed to stop process: {e}")
        finally:
            self.cleanup()
    
    def restart(self, **kwargs) -> bool:
        """
        Restart the WAF proxy process
        
        Args:
            **kwargs: Arguments passed to start()
            
        Returns:
            True if restarted successfully
        """
        self.logger.info("Restarting WAF proxy")
        
        # Stop current process
        if self.is_running():
            self.stop()
        
        # Start new process
        return self.start(**kwargs)
    
    def is_running(self) -> bool:
        """Check if the process is running"""
        if self.process is None:
            return False
        
        return self.process.poll() is None
    
    def get_pid(self) -> Optional[int]:
        """Get process PID"""
        return self.process.pid if self.process else None
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get process status information
        
        Returns:
            Status information dictionary
        """
        if not self.is_running():
            return {
                'running': False,
                'pid': None,
                'uptime': None,
                'restart_count': self.restart_count
            }
        
        uptime = datetime.now() - self.start_time if self.start_time else None
        
        status = {
            'running': True,
            'pid': self.process.pid,
            'uptime': uptime.total_seconds() if uptime else None,
            'restart_count': self.restart_count,
            'auto_restart': self.auto_restart
        }
        
        # Add process stats if available
        if self.monitor:
            try:
                stats = self.monitor.get_process_stats()
                status.update({
                    'cpu_percent': stats.cpu_percent,
                    'memory_mb': stats.memory_mb,
                    'threads': stats.threads,
                    'open_files': stats.open_files,
                    'connections': stats.connections
                })
            except ProcessError:
                pass
        
        return status
    
    def get_logs(self, lines: int = 100) -> List[str]:
        """
        Get recent log lines
        
        Args:
            lines: Number of recent lines to return
            
        Returns:
            List of log lines
        """
        logs = []
        temp_queue = queue.Queue()
        
        # Drain current queue into temp
        while not self.log_queue.empty():
            try:
                temp_queue.put(self.log_queue.get_nowait())
            except queue.Empty:
                break
        
        # Get logs from temp queue
        while not temp_queue.empty():
            try:
                logs.append(temp_queue.get_nowait())
            except queue.Empty:
                break
        
        # Return most recent lines
        return logs[-lines:] if logs else []
    
    def send_signal(self, sig: int) -> bool:
        """
        Send signal to process
        
        Args:
            sig: Signal number
            
        Returns:
            True if signal sent successfully
        """
        if not self.is_running():
            raise ProcessError("Process is not running")
        
        try:
            os.kill(self.process.pid, sig)
            self.logger.info(f"Sent signal {sig} to process {self.process.pid}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send signal: {e}")
            raise ProcessError(f"Failed to send signal: {e}")
    
    def reload_config(self) -> bool:
        """
        Reload configuration (sends SIGHUP)
        
        Returns:
            True if reload signal sent successfully
        """
        return self.send_signal(signal.SIGHUP)
    
    def cleanup(self):
        """Clean up resources"""
        # Stop monitoring
        if self.monitor:
            self.monitor.stop_monitoring()
            self.monitor = None
        
        # Stop log capture
        self._stop_log_capture()
        
        # Clean up process references
        self.process = None
        self.psutil_process = None
        self.start_time = None
    
    def _validate_config(self) -> bool:
        """Validate configuration by running with --validate-config"""
        try:
            result = subprocess.run(
                [str(self.binary_path), "--config", str(self.config_path), "--validate-config"],
                cwd=self.working_dir,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.info("Configuration validation passed")
                return True
            else:
                self.logger.error(f"Configuration validation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Configuration validation timed out")
            return False
        except Exception as e:
            self.logger.error(f"Configuration validation error: {e}")
            return False
    
    def _process_event_callback(self, event: str, data: Dict[str, Any]):
        """Handle process monitoring events"""
        self.logger.info(f"Process event: {event} - {data}")
        
        if event == 'process_died' and self.auto_restart:
            if self._should_restart():
                self.logger.info("Auto-restarting process")
                try:
                    self.restart()
                except Exception as e:
                    self.logger.error(f"Auto-restart failed: {e}")
            else:
                self.logger.error("Max restart attempts reached, disabling auto-restart")
                self.auto_restart = False
    
    def _should_restart(self) -> bool:
        """Check if process should be auto-restarted"""
        now = datetime.now()
        
        # Reset restart count if outside the restart window
        if (self.start_time and 
            now - self.start_time > self.restart_window):
            self.restart_count = 0
        
        self.restart_count += 1
        return self.restart_count <= self.max_restarts
    
    def _start_log_capture(self):
        """Start capturing process logs"""
        if self.process and self.process.stdout:
            self.log_thread = threading.Thread(
                target=self._log_capture_loop,
                daemon=True
            )
            self.log_thread.start()
    
    def _stop_log_capture(self):
        """Stop log capture thread"""
        if self.log_thread and self.log_thread.is_alive():
            # Log thread will stop when process terminates
            pass
    
    def _log_capture_loop(self):
        """Log capture loop"""
        if not self.process or not self.process.stdout:
            return
        
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    # Add timestamp and put in queue
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_line = f"[{timestamp}] {line.strip()}"
                    
                    # Keep queue size manageable
                    if self.log_queue.qsize() > 1000:
                        try:
                            self.log_queue.get_nowait()
                        except queue.Empty:
                            pass
                    
                    self.log_queue.put(log_line)
                    
                    # Also log to our logger
                    self.logger.debug(f"WAF: {line.strip()}")
        except Exception as e:
            self.logger.error(f"Log capture error: {e}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.is_running():
            self.stop()
        self.cleanup()
