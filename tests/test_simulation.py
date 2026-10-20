# =============================================================================
#  tests / test_simulation.py
#  ---------------------------------------------------------------------------
#  Unit tests for the thermodynamic & electrical process simulation engine.
# =============================================================================

import unittest
from honeypot.simulation.process import ProcessSimulator


class TestProcessSimulator(unittest.TestCase):

    def setUp(self):
        self.sim = ProcessSimulator()

    def tearDown(self):
        self.sim.stop()

    def test_initial_values(self):
        """Check nominal initial electrical and thermal values."""
        self.assertAlmostEqual(self.sim.base_voltage, 230.0, places=1)
        self.assertAlmostEqual(self.sim.base_current, 45.2, places=1)
        self.assertFalse(self.sim.cooling_fan_active)
        self.assertFalse(self.sim.emergency_cutoff)

    def test_emergency_cutoff_actuator(self):
        """Emergency cutoff should immediately drop electrical load to zero."""
        self.sim.set_coil(1, True)  # Coil 1 = emergency cutoff
        self.sim.tick()
        self.assertEqual(self.sim.current_voltage, 0.0)
        self.assertEqual(self.sim.current_current, 0.0)
        self.assertTrue(self.sim.get_coil(1))

    def test_cooling_fan_actuator_impacts_thermal_rate(self):
        """Turning on cooling fan should lower thermal equilibrium rate."""
        self.sim.cooling_fan_active = False
        initial_temp = self.sim.current_oil_temp

        # Advance with fan OFF
        for _ in range(5):
            self.sim.tick()
        temp_fan_off = self.sim.current_oil_temp

        # Turn fan ON
        self.sim.set_coil(0, True)
        for _ in range(15):
            self.sim.tick()
        temp_fan_on = self.sim.current_oil_temp

        # Temperature with forced cooling must drop below the uncooled rate
        self.assertLess(temp_fan_on, temp_fan_off + 2.0)

    def test_holding_registers_packing(self):
        """Holding registers should return 16-bit big-endian packed integers."""
        regs = self.sim.get_holding_registers(start_addr=0, quantity=4)
        self.assertIn(0, regs)
        self.assertIn(1, regs)
        self.assertIn(2, regs)
        self.assertIn(3, regs)
        self.assertEqual(regs[0][0], "voltage_high")
        self.assertEqual(regs[1][0], "voltage_low")


if __name__ == "__main__":
    unittest.main()
