# =============================================================================
#  ics_honeypot / simulation / process.py
#  ---------------------------------------------------------------------------
#  Dynamic Industrial Process Simulation Engine
#  ---------------------------------------------------------------------------
#  Real-world ICS honeypots often fail because attackers notice that sensor
#  values are completely static over time, or that actuator writes (FC05/FC06)
#  produce zero change in subsequent state reads.
#
#  This module provides a medium-interaction physical process simulator:
#    • Simulates a high-voltage electrical substation / cooling system
#    • Dynamic thermodynamic drift and grid voltage noise
#    • Interactive actuator state: Writing to coils/registers affects the physics!
#      - Turning ON Cooling Fan (Coil 0) lowers oil/ambient temperature
#      - Turning ON Emergency Cutoff (Coil 1) drops current/power to zero
#    • Thread-safe state access for Modbus and DNP3 listeners
# =============================================================================

import math
import random
import time
import threading
from typing import Dict, Any, Tuple


class ProcessSimulator:
    """
    Simulates a Substation Transformer Cooling & Electrical Subsystem.
    Provides realistic sensor dynamics and interactive actuator feedback.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._last_update = time.time()

        # Actuators (State controlled by attacker writes)
        self.cooling_fan_active: bool = False       # Modbus Coil 0 / DNP3 Binary Out 0
        self.emergency_cutoff: bool = False         # Modbus Coil 1 / DNP3 Binary Out 1
        self.aux_pump_active: bool = True           # Modbus Coil 2

        # Physical Process Variables (Base values)
        self.base_voltage: float = 230.0            # Volts (nominal RMS)
        self.base_current: float = 45.2             # Amperes (nominal load)
        self.ambient_temp: float = 28.5             # °C
        self.oil_temp: float = 58.4                 # °C (transformer oil)
        self.tank_pressure: float = 1013.2          # hPa
        self.humidity: float = 54.0                 # %

        # Dynamic live readings
        self.current_voltage: float = self.base_voltage
        self.current_current: float = self.base_current
        self.current_oil_temp: float = self.oil_temp
        self.current_pressure: float = self.tank_pressure
        self.current_humidity: float = self.humidity

        # Background simulation ticker
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="ProcessSimulator")
        self._thread.start()

    def stop(self):
        """Stop background simulation updates."""
        self._running = False

    def _run_loop(self):
        """Periodic simulation tick to model thermal and electrical physics."""
        while self._running:
            self.tick()
            time.sleep(1.0)

    def tick(self):
        """Advance the physical simulation state based on elapsed time."""
        with self._lock:
            now = time.time()
            dt = now - self._last_update
            self._last_update = now

            # 1. Electrical Grid Dynamics (Harmonics & load fluctuation)
            if self.emergency_cutoff:
                self.current_current = 0.0
                self.current_voltage = 0.0
            else:
                # Small AC grid fluctuation: ±1.2V sinusoidal wave + Gaussian noise
                noise = random.gauss(0, 0.25)
                wave = 1.2 * math.sin(now * 0.1)
                self.current_voltage = max(215.0, min(245.0, self.base_voltage + wave + noise))

                # Current varies with load
                load_noise = random.gauss(0, 0.4)
                self.current_current = max(0.0, self.base_current + (wave * 0.3) + load_noise)

            # 2. Thermal Physics: Heating vs. Cooling
            # Heating rate proportional to electrical load (I^2 * R heating effect)
            heat_gen = 0.08 * (self.current_current / self.base_current)

            # Cooling rate: Ambient dissipation + Fan cooling effect
            cooling_rate = 0.03
            if self.cooling_fan_active:
                cooling_rate += 0.12  # Forced cooling lowers temperature substantially

            if self.current_current > 0:
                self.current_oil_temp += (heat_gen - cooling_rate) * dt
            else:
                # System cooling down to ambient
                self.current_oil_temp -= 0.15 * dt

            # Constrain oil temperature to plausible operating range (30°C - 95°C)
            self.current_oil_temp = max(30.0, min(95.0, self.current_oil_temp))

            # 3. Tank Pressure (ideal gas law response to temperature)
            temp_kelvin = self.current_oil_temp + 273.15
            self.current_pressure = 1013.2 * (temp_kelvin / (58.4 + 273.15)) + random.gauss(0, 0.1)

            # 4. Humidity slight drift
            self.current_humidity = max(40.0, min(75.0, self.humidity + 0.5 * math.cos(now * 0.05)))

    # -------------------------------------------------------------------------
    # Actuator State Control (Triggered by attacker writes)
    # -------------------------------------------------------------------------

    def set_coil(self, coil_addr: int, value: bool):
        """Handle actuator state change from Modbus FC05/FC15 or DNP3."""
        with self._lock:
            if coil_addr == 0:
                self.cooling_fan_active = value
            elif coil_addr == 1:
                self.emergency_cutoff = value
            elif coil_addr == 2:
                self.aux_pump_active = value

    def get_coil(self, coil_addr: int) -> bool:
        """Read digital output (coil) state."""
        with self._lock:
            if coil_addr == 0:
                return self.cooling_fan_active
            elif coil_addr == 1:
                return self.emergency_cutoff
            elif coil_addr == 2:
                return self.aux_pump_active
            return False

    def get_discrete_input(self, input_addr: int) -> bool:
        """Read digital input status (e.g. alarm flags)."""
        with self._lock:
            if input_addr == 0:
                # High temperature alarm flag (> 75°C)
                return self.current_oil_temp > 75.0
            elif input_addr == 1:
                # Grid breaker closed flag
                return not self.emergency_cutoff
            elif input_addr == 2:
                # Pressure anomaly flag
                return self.current_pressure > 1030.0
            return False

    # -------------------------------------------------------------------------
    # Register Mapping (Modbus / DNP3)
    # -------------------------------------------------------------------------

    def get_holding_registers(self, start_addr: int, quantity: int) -> Dict[int, Tuple[str, int]]:
        """
        Produce dynamic holding register values (integer × 10 representation).
        """
        with self._lock:
            v_int = int(round(self.current_voltage * 10))
            i_int = int(round(self.current_current * 10))
            t_int = int(round(self.current_oil_temp * 10))
            p_int = int(round(self.current_pressure * 10))
            h_int = int(round(self.current_humidity * 10))

            full_map = {
                0: ("voltage_high", (v_int >> 8) & 0xFF),
                1: ("voltage_low", v_int & 0xFF),
                2: ("current_high", (i_int >> 8) & 0xFF),
                3: ("current_low", i_int & 0xFF),
                4: ("temp_high", (t_int >> 8) & 0xFF),
                5: ("temp_low", t_int & 0xFF),
                6: ("pressure_high", (p_int >> 8) & 0xFF),
                7: ("pressure_low", p_int & 0xFF),
                8: ("humidity_high", (h_int >> 8) & 0xFF),
                9: ("humidity_low", h_int & 0xFF),
            }

            result = {}
            for i in range(quantity):
                addr = start_addr + i
                if addr in full_map:
                    result[addr] = full_map[addr]
                else:
                    result[addr] = (f"reg_{addr}", 0x0000)
            return result

    def get_telemetry_dict(self) -> Dict[str, Any]:
        """Return snapshot of current physical process state for telemetry/reporting."""
        with self._lock:
            return {
                "voltage_v": round(self.current_voltage, 1),
                "current_a": round(self.current_current, 1),
                "oil_temp_c": round(self.current_oil_temp, 1),
                "pressure_hpa": round(self.current_pressure, 1),
                "humidity_pct": round(self.current_humidity, 1),
                "cooling_fan": "ON" if self.cooling_fan_active else "OFF",
                "emergency_cutoff": "TRIGGERED" if self.emergency_cutoff else "NORMAL",
            }


# Global singleton instance of process simulator
simulator = ProcessSimulator()
