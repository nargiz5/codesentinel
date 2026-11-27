"""Passes user input to a helper defined in another module."""
from service_utils import restart

restart(input("Service: "))
